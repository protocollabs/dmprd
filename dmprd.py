#!/usr/bin/python3
# -*- coding: utf-8 -*- 

import asyncio
import socket
import struct
import binascii
import time
import sys
import functools
import argparse
import signal
import os
import json
import datetime
import urllib.request
import pprint
import logging

import core.dmpr
import utils.id
import httpd.httpd

log = logging.getLogger()

class ConfigurationException(Exception): pass

TX_DEFAULT_TTL = 8
RECVFROM_BUF_SIZE = 16384

# don't recognize own mcast transmissions
# by default, can be changed for debugging
MCAST_LOOP = 0



class LoggerClone:


    def __init__(self):
        pass

    def msg(self, msg, time=None):
        if not time:
            time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        msg = "{}: {}\n".format(time, msg)
        sys.stderr.write(msg)

    debug = msg
    info = msg
    warning = msg
    error = msg
    critical = msg


def cb_routing_table_update(routing_tables, priv_data=None):
    assert(priv_data)
    ctx = priv_data
    ctx['routing-tables'] = routing_tables
    broadcast_routing_table(ctx)


def create_routing_packet(msg):
    msg_json = json.dumps(msg)
    return str.encode(msg_json)


def decreate_routing_packet(msg):
    ascii_str = msg.decode('ascii')
    return json.loads(ascii_str)


def tx_v4(ctx, iface, mcast_addr, pkt):
    port = int(ctx['conf']['core']['port'])
    fd = ctx['iface'][iface]['v4-tx-fd']
    try:
        print("send v4 rtn packet tp {}:{}".format(mcast_addr, port))
        fd.sendto(pkt, (mcast_addr, port))
    except Exception as e:
        print("Exception: {}".format(str(e)))


def tx_v6(ctx, iface, mcast_addr, pkt):
    port = int(ctx['conf']['core']['port'])
    fd = ctx['iface'][iface]['v6-tx-fd']
    try:
        print("send v6 rtn packet tp {}:{}".format(mcast_addr, port))
        fd.sendto(pkt, (mcast_addr, port))
    except Exception as e:
        print("Exception: {}".format(str(e)))


def cb_msg_tx(iface_name, proto, mcast_addr, msg, priv_data=None):
    assert priv_data
    ctx = priv_data
    pkt = create_routing_packet(msg)
    if proto == 'v4':
        tx_v4(ctx, iface_name, mcast_addr, pkt)
    if proto == 'v6':
        tx_v6(ctx, iface_name, mcast_addr, pkt)


def cb_time(priv_data=None):
    return time.clock_gettime(time.CLOCK_MONOTONIC_RAW)


def setup_core(ctx):
    log = LoggerClone()
    ctx['core'] = core.dmpr.DMPR(log=log)

    ctx['core'].register_configuration(ctx['conf']['core'])

    ctx['core'].register_routing_table_update_cb(cb_routing_table_update, priv_data=ctx)
    ctx['core'].register_msg_tx_cb(cb_msg_tx, priv_data=ctx)
    ctx['core'].register_get_time_cb(cb_time, priv_data=ctx)


def cb_v4_rx(fd, ctx, interface):
    try:
        data, addr = fd.recvfrom(RECVFROM_BUF_SIZE)
        src_addr = addr[0]
        src_port = addr[1]
        iface_name = interface['name']
        print("receive v4 rtn packet: {}:{} [{}]".format(src_addr, src_port, iface_name))
    except socket.error as e:
        print('Expection: {}'.format(str(e)))
    msg = decreate_routing_packet(data)
    ctx['core'].msg_rx(iface_name, msg)


def cb_v6_rx(fd, ctx, interface):
    try:
        data, addr = fd.recvfrom(RECVFROM_BUF_SIZE)
        src_addr = addr[0]
        src_port = addr[1]
        iface_name = interface['name']
        print("receive v6 rtn packet: {}:{} [{}]".format(src_addr, src_port, iface_name))
    except socket.error as e:
        print('Expection: {}'.format(str(e)))
    msg = decreate_routing_packet(data)
    ctx['core'].msg_rx(iface_name, msg)



def parse_payload_header(raw):
    if len(raw) < len(IDENT) + 4:
        # check for minimal length
        # ident(3) + size(>=4) + payload(>=1)
        print("Header to short")
        return False
    ident = raw[0:3]
    if ident != IDENT:
        print("ident wrong: expect:{} received:{}".format(IDENT, ident))
        return False
    return True


def parse_payload_data(raw):
    size = struct.unpack('>I', raw[3:7])[0]
    if len(raw) < 7 + size:
        print("message seems corrupt")
        return False, None
    data = raw[7:7 + size]
    uncompressed_json = str(zlib.decompress(data), "utf-8")
    data = json.loads(uncompressed_json)
    return True, data


def self_check(data):
    if data["cookie"] == SECRET_COOKIE:
        return True
    return False


def parse_payload(packet):
    ok = parse_payload_header(packet["data"])
    if not ok: return

    ok, data = parse_payload_data(packet["data"])
    if not ok: return

    self = self_check(data)
    if self: return

    ret = {}
    ret["src-addr"] = packet["src-addr"]
    ret["src-port"] = packet["src-port"]
    ret["payload"] = data
    return ret


def ctx_new(conf):
    ctx = {}
    ctx['conf'] = conf
    ctx['iface'] = dict()
    ctx['queue'] = asyncio.Queue(32)
    ctx['routing-tables'] = None
    return ctx


def db_entry_update(db_entry, data, prefix):
    if db_entry[1]["src-ip"] != data["src-addr"]:
        print("WARNING, seems another router ({}) also announce {}".format(data["src-addr"], prefix))
        db_entry[1]["src-ip"] = data["src-addr"]
    print("route refresh for {} by {}".format(db_entry[0], data["src-addr"]))
    db_entry[1]["last-seen"] = datetime.datetime.utcnow()


def db_entry_new(conf, db, data, prefix):
    entry = []
    entry.append(prefix)

    second_element = {}
    second_element["src-ip"] = data["src-addr"]
    second_element["last-seen"] = datetime.datetime.utcnow()
    entry.append(second_element)

    db["networks"].append(entry)
    print("new route announcement for {} by {}".format(prefix, data["src-addr"]))


def rx_v4_socket_create(port, mcast_addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(sock, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, MCAST_LOOP)

    sock.bind(('', port))
    host = socket.gethostbyname(socket.gethostname())
    sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))

    mreq = struct.pack("4sl", socket.inet_aton(mcast_addr), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock


def tx_v4_socket_create(addr, ttl):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(addr))
    return sock


def init_socket_v4_tx(ctx, iface):
    addr_v4 = iface['addr-v4']
    ttl = TX_DEFAULT_TTL
    if 'ttl-v4' in iface:
        ttl = int(iface['ttl-v4'])
    ctx['iface'][iface['name']]['v4-tx-fd'] = tx_v4_socket_create(addr_v4, ttl)


def init_socket_v4_rx(ctx, interface):
    port = int(ctx['conf']['core']['port'])
    mcast_addr = ctx['conf']['core']['mcast-v4-tx-addr']
    fd = rx_v4_socket_create(port, mcast_addr)
    ctx['loop'].add_reader(fd, functools.partial(cb_v4_rx, fd, ctx, interface))


def init_sockets_v4(ctx, interface):
    init_socket_v4_tx(ctx, interface)
    init_socket_v4_rx(ctx, interface)


def tx_v6_socket_create(addr, ttl):
    addrinfo = socket.getaddrinfo(addr, None)[0]
    sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
    return sock


def init_socket_v6_tx(ctx, iface):
    addr_v6 = ctx['conf']['core']['mcast-v6-tx-addr']
    ttl = TX_DEFAULT_TTL
    if 'ttl-v6' in iface:
        ttl = int(iface['ttl-v6'])
    ctx['iface'][iface['name']]['v6-tx-fd'] = tx_v6_socket_create(addr_v6, ttl)


def rx_v6_socket_create(port, mcast_addr):
    addrinfo = socket.getaddrinfo(mcast_addr, None)[0]
    sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(sock, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, MCAST_LOOP)

    sock.bind(('', port))
    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
    mreq = group_bin + struct.pack('@I', 0)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    return sock


def init_socket_v6_rx(ctx, interface):
    port = int(ctx['conf']['core']['port'])
    mcast_addr = ctx['conf']['core']['mcast-v6-tx-addr']
    fd = rx_v6_socket_create(port, mcast_addr)
    ctx['loop'].add_reader(fd, functools.partial(cb_v6_rx, fd, ctx, interface))


def init_sockets_v6(ctx, interface):
    init_socket_v6_tx(ctx, interface)
    init_socket_v6_rx(ctx, interface)


def init_sockets(ctx):
    for interface in ctx['conf']['core']['interfaces']:
        iface_name = interface['name']
        if not iface_name in ctx['iface']:
            ctx['iface'][iface_name] = dict()
        if "addr-v4" in interface:
            init_sockets_v4(ctx, interface)
        if "addr-v6" in interface:
            init_sockets_v6(ctx, interface)


async def ticker(ctx):
    while True:
        try:
            await asyncio.sleep(1)
            ctx['core'].tick()
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()


def path_metric_profile_rewrite(ctx, table_name):
    """ convert from internal name to rewrite name if specified"""
    for profile in ctx['conf']['core']['path-metric-profiles']:
        if not "rewrite" in profile:
            continue
        if profile['name'] == table_name:
            return profile['rewrite']
        if 'status' in profile and profile['status'] not in ("enabled", "true"):
            log.error("table should not be calculated at all, internal error")
            continue
    return table_name


def create_ip_routing_data(ctx, tables):
    data = list()
    tables = ctx['routing-tables']
    for table_name, table_list in tables.items():
        for route_entry in table_list:
            new_entry = {}
            new_entry['table-name'] = path_metric_profile_rewrite(ctx, table_name)
            new_entry['prefix'] = route_entry['prefix']
            new_entry['prefix-len'] = route_entry['prefix-len']
            new_entry['interface'] = route_entry['interface']
            new_entry['next-hop'] = route_entry['next-hop']
            data.append(new_entry)
    return data


def broadcast_routing_table(ctx):
    if not ctx['routing-tables']:
        print("no routing table calculated, no info forwarded, yet")
        return
    print("\nRouting table:")
    pprint.pprint(ctx['routing-tables'])
    print("\n")
    url = ctx['conf']['route-info-broadcaster']['url']
    #print("write routing table to {}".format(url))
    # just ignore any configured system proxy, we don't need
    # a proxy for localhost communication
    proxy_support = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_support)
    urllib.request.install_opener(opener)
    req = urllib.request.Request(url)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('User-Agent', 'Mozilla/5.0 (compatible; Chrome/22.0.1229.94; Windows NT)')
    data = create_ip_routing_data(ctx, ctx['routing-tables'])
    tx_data = json.dumps(data).encode('utf-8')
    try:
        with urllib.request.urlopen(req, tx_data, timeout=3) as res:
            resp = json.loads(str(res.read(), "utf-8"))
            print(pprint.pformat(resp))
    except urllib.error.URLError as e:
        print("Connection error: {}".format(e))


async def route_broadcast(ctx):
    interval = 10
    if "interval" in ctx['conf']['route-info-broadcaster']:
        interval = ctx['conf']['route-info-broadcaster']['interval']
    while True:
        try:
            await asyncio.sleep(interval)
            broadcast_routing_table(ctx)
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()



def shutdown_dmprd(signame, ctx):
    sys.stderr.write("\rreceived signal \"%s\": exit now, bye\n" % signame)
    if 'core' in ctx:
        ctx['core'].stop()
    for task in asyncio.Task.all_tasks():
        task.cancel()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--configuration", help="configuration", type=str, default=None)
    args = parser.parse_args()
    if not args.configuration:
        print("Configuration required, please specify a valid file path, exiting now")
        sys.exit(1)
    return args


def verify_conf(conf):
    if not "core" in conf:
        msg = "conf invalid, need core part"
        raise ConfigurationException(msg)
    core = conf['core']
    if not "interfaces" in core:
        msg = "Configuration invalid, interfaces not in core"
        raise ConfigurationException(msg)


def load_configuration_file(args):
    with open(args.configuration) as json_data:
        conf = json.load(json_data)
        verify_conf(conf)
        return conf


def conf_init():
    args = parse_args()
    return load_configuration_file(args)


def init_logging(conf):
    log_level_conf = "warning"
    if "logging" in conf['core']:
        if "level" in conf['core']["logging"]:
            log_level_conf = conf['core']["logging"]['level']
    numeric_level = getattr(logging, log_level_conf.upper(), None)
    if not isinstance(numeric_level, int):
        raise ConfigurationException('Invalid log level: {}'.format(numeric_level))
    logging.basicConfig(level=numeric_level, format='%(message)s')
    log.error("Log level configuration: {}".format(log_level_conf))


def verify_conf_id(ctx):
    # in the configuration file the id MAY be given, if not we
    # generate a random one. To be a "stable" citizen we save the
    # id permanently and resuse it as server start (if available)
    utils.id.check_and_patch_id(ctx)


def main():
    sys.stderr.write("Dynamic MultiPath Routing Daemon - 2016, 2017\n")
    conf = conf_init()
    init_logging(conf)
    ctx = ctx_new(conf)

    verify_conf_id(ctx)

    ctx['loop'] = asyncio.get_event_loop()
    ctx['loop'].set_debug(True)

    if 'httpd' in ctx['conf']:
        print('Start HTTPD')
        ctx['httpd'] = httpd.httpd.Httpd(ctx)

    init_sockets(ctx)
    setup_core(ctx)
    asyncio.ensure_future(ticker(ctx))
    if "route-info-broadcaster" in ctx['conf']:
        asyncio.ensure_future(route_broadcast(ctx))

    ctx['core'].start()


    for signame in ('SIGINT', 'SIGTERM'):
        ctx['loop'].add_signal_handler(getattr(signal, signame),
                                       functools.partial(shutdown_dmprd, signame, ctx))
    try:
        ctx['loop'].run_forever()
        # workaround for bug, see: https://bugs.python.org/issue23548
        ctx['loop'].close()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
