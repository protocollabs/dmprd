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
import uuid
import json
import datetime
import urllib.request
import urllib.error

class ConfigurationException(Exception): pass

TX_DEFAULT_TTL = 8
RECVFROM_BUF_SIZE = 16384

# don't recognize own mcast transmissions
# by default, can be changed for debugging
MCAST_LOOP = 0

# ident to drop all non-RouTinG applications.
IDENT = "RTG".encode('ascii')

# identify this sender
SECRET_COOKIE = str(uuid.uuid4())

# data compression level
ZIP_COMPRESSION_LEVEL = 9


def init_v4_rx_fd(conf):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(sock, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, MCAST_LOOP)

    sock.bind(('', int(conf['core']['v4-port'])))
    host = socket.gethostbyname(socket.gethostname())
    sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))

    mreq = struct.pack("4sl", socket.inet_aton(conf['core']['v4-addr']), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock


def init_v4_tx_fd(conf):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, int(conf['core']['v4-ttl']))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(conf['core']['v4-out-addr']))
    return sock


def cb_v4_rx(fd, ctx):
    try:
        data, addr = fd.recvfrom(RECVFROM_BUF_SIZE)
    except socket.error as e:
        print('Expection')
    d = {}
    d["proto"] = "IPv4"
    d["src-addr"]  = addr[0]
    d["src-port"]  = addr[1]
    d["data"]  = data
    try:
        pass
        #queue.put_nowait(d)
    except asyncio.queues.QueueFull:
        sys.stderr.write("queue overflow, strange things happens")


def cb_v6_rx(fd, ctx):
    try:
        data, addr = fd.recvfrom(RECVFROM_BUF_SIZE)
    except socket.error as e:
        print('Expection')
    d = {}
    d["proto"] = "IPv6"
    d["src-addr"]  = addr[0]
    d["src-port"]  = addr[1]
    d["data"]  = data
    try:
        pass
        #queue.put_nowait(d)
    except asyncio.queues.QueueFull:
        sys.stderr.write("queue overflow, strange things happens")



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
    db = {}
    db['conf'] = conf
    db['queue'] = asyncio.Queue(32)
    return db


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


async def ticker(ctx):
    while True:
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            break
    asyncio.get_event_loop().stop()


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


def init_socket_v4_tx(ctx, interface):
    addr_v4 = interface['addr-v4']
    ttl = TX_DEFAULT_TTL
    if 'ttl-v4' in interface:
        ttl = int(interface['ttl-v4'])
    ctx['v4-tx-fd'] = tx_v4_socket_create(addr_v4, ttl)


def init_socket_v4_rx(ctx, interface):
    port = int(ctx['conf']['core']['port'])
    mcast_addr = ctx['conf']['core']['mcast-v4-tx-addr']
    fd = rx_v4_socket_create(port, mcast_addr)
    ctx['loop'].add_reader(fd, functools.partial(cb_v4_rx, fd, ctx))


def init_sockets_v4(ctx, interface):
    init_socket_v4_tx(ctx, interface)
    init_socket_v4_rx(ctx, interface)


def tx_v6_socket_create(addr, ttl):
    addrinfo = socket.getaddrinfo(addr, None)[0]
    sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
    return sock


def init_socket_v6_tx(ctx, interface):
    addr_v6 = ctx['conf']['core']['mcast-v6-tx-addr']
    ttl = TX_DEFAULT_TTL
    if 'ttl-v6' in interface:
        ttl = int(interface['ttl-v6'])
    ctx['v6-tx-fd'] = tx_v6_socket_create(addr_v6, ttl)


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
    ctx['loop'].add_reader(fd, functools.partial(cb_v6_rx, fd, ctx))


def init_sockets_v6(ctx, interface):
    init_socket_v6_tx(ctx, interface)
    init_socket_v6_rx(ctx, interface)


def init_sockets(ctx):
    for interface in ctx['conf']['core']['interfaces']:
        if "addr-v4" in interface:
            init_sockets_v4(ctx, interface)
        if "addr-v6" in interface:
            init_sockets_v6(ctx, interface)


def ask_exit(signame, ctx):
    sys.stderr.write("\rreceived signal \"%s\": exit now, bye\n" % signame)
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


def main():
    print("Dynamic MultiPath Routing Daemon - 2016, 2017")
    conf = conf_init()
    ctx = ctx_new(conf)

    ctx['loop'] = asyncio.get_event_loop()
    ctx['loop'].set_debug(True)


    init_sockets(ctx)
    asyncio.ensure_future(ticker(ctx))

    for signame in ('SIGINT', 'SIGTERM'):
        ctx['loop'].add_signal_handler(getattr(signal, signame),
                                       functools.partial(ask_exit, signame, ctx))
    try:
        ctx['loop'].run_forever()
        # workaround for bug, see: https://bugs.python.org/issue23548
        ctx['loop'].close()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
