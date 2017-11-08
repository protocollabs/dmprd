#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

import argparse
import asyncio
import datetime
import functools
import json
import logging
import pprint
import signal
import socket
import struct
import time
import urllib.error
import urllib.request
import zlib

import core.dmpr
import httpd.httpd
import utils.id

logger = logging.getLogger()


class ConfigurationException(Exception):
    pass


TX_DEFAULT_TTL = 8
RECVFROM_BUF_SIZE = 16384

# don't recognize own mcast transmissions
# by default, can be changed for debugging
MCAST_LOOP = 0


def get_ip_mreqn_struct(multicast_address, interface_address, interface_name):
    """
    Set up a mreqn struct to define the interface we want to bind to
    """
    # See https://github.com/torvalds/linux/blob/866ba84ea30f94838251f74becf3cfe3c2d5c0f9/include/uapi/linux/in.h#L168
    ip_mreqn = socket.inet_aton(multicast_address)
    ip_mreqn += socket.inet_aton(interface_address)
    ip_mreqn += struct.pack('@i', socket.if_nametoindex(interface_name))
    return ip_mreqn


class MulticastTxSocket(socket.socket):
    def __init__(self, multicast_address: str, interface_address: str,
                 interface_name: str, ttl: int):
        addrinfo = socket.getaddrinfo(interface_address, None)[0]
        super(MulticastTxSocket, self).__init__(addrinfo[0], socket.SOCK_DGRAM)

        if hasattr(socket, 'SO_REUSEADDR'):
            self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        ttl_bin = struct.pack('@i', ttl)

        if addrinfo[0] == socket.AF_INET:
            # IPv4 specific socket configuration

            ip_mreqn = get_ip_mreqn_struct(multicast_address, interface_address,
                                           interface_name)
            self.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            ip_mreqn)
            # Set the TTL
            self.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

        elif addrinfo[0] == socket.AF_INET6:
            # IPv6 specific socket configuration

            # IPv6 wants just the interface index, wrapped in a struct
            iface_index = socket.if_nametoindex(interface_name)
            self.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                            struct.pack('@i', iface_index))
            # Set the TTL
            self.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS,
                            ttl_bin)

    def send_multicast_packet(self, data, multicast_addr, port):
        """
        Send a multicast packet to the specified address
        """
        try:
            self.sock.sendto(data, (multicast_addr, port))
        except Exception as e:
            logger.exception('Error while sending packet', exc_info=e)


class MulticastRxSocket(socket.socket):
    def __init__(self, multicast_address: str, port: int,
                 interface_address: str, interface_name: str):
        addrinfo = socket.getaddrinfo(multicast_address, None)[0]
        iface_index = socket.if_nametoindex(interface_name)

        super(MulticastRxSocket, self).__init__(addrinfo[0], socket.SOCK_DGRAM)

        if hasattr(socket, 'SO_REUSEADDR'):
            self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.bind((multicast_address, port))

        if addrinfo[0] == socket.AF_INET:
            ip_mreqn = get_ip_mreqn_struct(multicast_address, interface_address,
                                           interface_name)
            self.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            ip_mreqn)

            # Allow looping if MCAST_LOOP is set to 1
            self.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP,
                            MCAST_LOOP)

        elif addrinfo[0] == socket.AF_INET6:
            # See https://github.com/torvalds/linux/blob/866ba84ea30f94838251f74becf3cfe3c2d5c0f9/include/uapi/linux/in6.h#L60
            # struct defines the multicast address and interface index
            ipv6_mreq = socket.inet_pton(addrinfo[0], addrinfo[4][0])
            ipv6_mreq += struct.pack('@i', iface_index)
            self.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                            ipv6_mreq)

            # Allow looping if MCAST_LOOP is set to 1
            self.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP,
                            MCAST_LOOP)


class DMPRD(object):
    def __init__(self, conf, event_loop):
        self.conf = conf
        self.event_loop = event_loop

        self.sockets = {}
        self.queue = asyncio.Queue(32)
        self.routing_table = None

        self.setup_core()
        self.init_sockets()

    def init_sockets(self):
        for interface in self.conf['core']['interfaces']:
            name = interface['name']

            if 'port' not in interface:
                emsg = 'port not specified in configuration file for interface {}'
                raise ConfigurationException(emsg.format(name))
            port = interface['port']

            self.sockets[name] = {}

            for proto in 'v4', 'v6':
                self._init_socket(proto, interface, port)

    def _init_socket(self, proto, interface, port):
        addr = interface.get('addr-{}'.format(proto), False)
        if not addr:
            return

        ttl = int(interface.get('ttl-{}'.format(proto), TX_DEFAULT_TTL))
        mcast_addr = self.conf['core']['mcast-{}-tx-addr'.format(proto)]
        name = interface['name']
        self.sockets[name][proto] = MulticastTxSocket(mcast_addr, addr, name,
                                                      ttl)
        rx = MulticastRxSocket(mcast_addr, port, addr, name)
        self.event_loop.add_reader(rx,
                                   functools.partial(self.cb_rx, rx, interface))

    def setup_core(self):
        self.core = core.dmpr.DMPR()
        self.core.register_configuration(self.conf['core'])

        self.core.register_routing_table_update_cb(self.cb_routing_table_update)
        self.core.register_msg_tx_cb(self.cb_msg_tx)
        self.core.register_get_time_cb(self.cb_time)

        self.core.register_policy(core.dmpr.SimpleLossPolicy())
        self.core.register_policy(core.dmpr.SimpleBandwidthPolicy())

    def start(self):
        asyncio.ensure_future(self.ticker())

    def stop(self, signame):
        logger.info('received signal {}: exit now, bye'.format(signame))
        self.core.stop()
        for task in asyncio.Task.all_tasks():
            task.cancel()

    async def ticker(self):
        while True:
            try:
                await asyncio.sleep(1)
                self.core.tick()
            except asyncio.CancelledError:
                break
        asyncio.get_event_loop().stop()

    ###########
    # tx path #
    ###########

    def cb_msg_tx(self, interface_name: str, proto: str, mcast_addr: str,
                  msg: dict):
        packet = create_routing_packet(msg)
        port = self.get_mcast_port(interface_name)
        fd = self.sockets[interface_name][proto]
        logger.info('send rtn packet tp {}:{}'.format(mcast_addr, port))
        fd.send_multicast_packet(packet, mcast_addr, port)

    ###########
    # rx path #
    ###########

    def cb_rx(self, sock, interface):
        try:
            data, addr = sock.recvfrom(RECVFROM_BUF_SIZE)
            src_addr = addr[0]
            src_port = addr[1]
            iface_name = interface['name']
            logger.info(
                'receive packet: {}:{} [{}]'.format(src_addr, src_port,
                                                    iface_name))
        except socket.error as e:
            logger.exception('error while receiving packet', exc_info=e)
            return

        msg = decreate_routing_packet(data)
        self.core.msg_rx(iface_name, msg)

    ############
    # internal #
    ############

    def cb_routing_table_update(self, routing_tables):
        self.routing_table = routing_tables
        # broadcast_routing_table(ctx)

    #########
    # utils #
    #########

    def get_mcast_port(self, interface):
        for e in self.conf['core']['interfaces']:
            if e['name'] == interface:
                return e['port']
        emsg = 'port not specified in configuration for interface {}'
        raise ConfigurationException(emsg.format(interface))

    @staticmethod
    def cb_time():
        return time.clock_gettime(time.CLOCK_MONOTONIC_RAW)


def create_routing_packet(msg):
    msg_json = json.dumps(msg)
    return str.encode(msg_json)


def decreate_routing_packet(msg):
    ascii_str = msg.decode('ascii')
    return json.loads(ascii_str)


def parse_payload_header(raw):
    if len(raw) < len(IDENT) + 4:
        # check for minimal length
        # ident(3) + size(>=4) + payload(>=1)
        logger.error("Header to short")
        return False
    ident = raw[0:3]
    if ident != IDENT:
        logger.error("ident wrong: expect:{} received:{}".format(IDENT, ident))
        return False
    return True


def parse_payload_data(raw):
    size = struct.unpack('>I', raw[3:7])[0]
    if len(raw) < 7 + size:
        logger.error("message seems corrupt")
        return False, None
    data = raw[7:7 + size]
    uncompressed_json = str(zlib.decompress(data), 'utf-8')
    data = json.loads(uncompressed_json)
    return True, data


def self_check(data):
    if data['cookie'] == SECRET_COOKIE:
        return True
    return False


def parse_payload(packet):
    ok = parse_payload_header(packet['data'])
    if not ok: return

    ok, data = parse_payload_data(packet['data'])
    if not ok: return

    self = self_check(data)
    if self: return

    ret = {}
    ret['src-addr'] = packet['src-addr']
    ret['src-port'] = packet['src-port']
    ret['payload'] = data
    return ret


def db_entry_update(db_entry, data, prefix):
    if db_entry[1]['src-ip'] != data['src-addr']:
        logger.warning(
            "WARNING, seems another router ({}) also announce {}".format(
                data['src-addr'], prefix))
        db_entry[1]['src-ip'] = data['src-addr']
    logger.info("route refresh for {} by {}".format(db_entry[0], data['src-addr']))
    db_entry[1]['last-seen'] = datetime.datetime.utcnow()


def db_entry_new(conf, db, data, prefix):
    entry = []
    entry.append(prefix)

    second_element = {}
    second_element['src-ip'] = data['src-addr']
    second_element['last-seen'] = datetime.datetime.utcnow()
    entry.append(second_element)

    db['networks'].append(entry)
    logger.info(
        "new route announcement for {} by {}".format(prefix, data['src-addr']))


def path_metric_profile_rewrite(ctx, table_name):
    """ convert from internal name to rewrite name if specified"""
    for profile in ctx['conf']['core']['path-metric-profiles']:
        if not 'rewrite' in profile:
            continue
        if profile['name'] == table_name:
            return profile['rewrite']
        if 'status' in profile and profile['status'] not in ('enabled', 'true'):
            logger.error(
                "table should not be calculated at all, internal error")
            continue
    return table_name


def create_ip_routing_data(ctx, tables):
    data = list()
    tables = ctx['routing-tables']
    for table_name, table_list in tables.items():
        for route_entry in table_list:
            new_entry = {}
            new_entry['table-name'] = path_metric_profile_rewrite(ctx,
                                                                  table_name)
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
    print()
    url = ctx['conf']['route-info-broadcaster']['url']
    # print('write routing table to {}'.format(url))
    # just ignore any configured system proxy, we don't need
    # a proxy for localhost communication
    proxy_support = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_support)
    urllib.request.install_opener(opener)
    req = urllib.request.Request(url)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('User-Agent',
                   'Mozilla/5.0 (compatible; Chrome/22.0.1229.94; Windows NT)')
    data = create_ip_routing_data(ctx, ctx['routing-tables'])
    tx_data = json.dumps(data).encode('utf-8')
    try:
        with urllib.request.urlopen(req, tx_data, timeout=3) as res:
            resp = json.loads(str(res.read(), 'utf-8'))
            print(pprint.pformat(resp))
    except urllib.error.URLError as e:
        print("Connection error: {}".format(e))


async def route_broadcast(ctx):
    interval = 10
    if 'interval' in ctx['conf']['route-info-broadcaster']:
        interval = ctx['conf']['route-info-broadcaster']['interval']
    while True:
        try:
            await asyncio.sleep(interval)
            broadcast_routing_table(ctx)
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()


def verify_conf(conf):
    if not 'core' in conf:
        msg = "conf invalid, need core part"
        raise ConfigurationException(msg)
    core = conf['core']
    if not 'interfaces' in core:
        msg = "Configuration invalid, interfaces not in core"
        raise ConfigurationException(msg)


def load_conf(args):
    conf = json.load(args.configuration)
    verify_conf(conf)
    utils.id.check_and_patch_id(conf)
    return conf


def main():
    parser = argparse.ArgumentParser(
        description="Dynamic MultiPath Routing Daemon - 2016, 2017")
    parser.add_argument('-f', '--configuration', help='Configuration file',
                        type=argparse.FileType('r'), required=True)
    args = parser.parse_args()

    conf = load_conf(args)

    event_loop = asyncio.get_event_loop()
    event_loop.set_debug(True)

    if 'httpd' in conf:
        logger.info("Start HTTPD")
        http_server = httpd.httpd.Httpd()

    dmprd = DMPRD(conf, event_loop)

    # if 'route-info-broadcaster' in conf:
    #    asyncio.ensure_future(route_broadcast({}))

    dmprd.start()

    for signame in ('SIGINT', 'SIGTERM'):
        event_loop.add_signal_handler(getattr(signal, signame),
                                      functools.partial(dmprd.stop, signame))
    try:
        event_loop.run_forever()
        # workaround for bug, see: https://bugs.python.org/issue23548
        event_loop.close()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
