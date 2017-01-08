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


def cb_v4_rx(fd, queue):
    try:
        data, addr = fd.recvfrom(1024)
    except socket.error as e:
        print('Expection')
    d = {}
    d["proto"] = "IPv4"
    d["src-addr"]  = addr[0]
    d["src-port"]  = addr[1]
    d["data"]  = data
    try:
        queue.put_nowait(d)
    except asyncio.queues.QueueFull:
        sys.stderr.write("queue overflow, strange things happens")

def create_payload_routing(conf, data):
    if "network-announcement" in conf:
        data["hna"] = conf["network-announcement"]

def create_payload_data(conf):
    data = {}
    data["cookie"] = SECRET_COOKIE
    create_payload_routing(conf, data)
    json_data = json.dumps(data)
    byte_stream = str.encode(json_data)
    compressed = zlib.compress(byte_stream, ZIP_COMPRESSION_LEVEL)
    #print("compression stats: before {} byte - after compression {} byte".format(len(byte_stream), len(compressed)))
    return compressed


def create_payload_header(data_len):
    ident = IDENT
    assert len(IDENT) == 3
    data = SECRET_COOKIE
    head = struct.pack('>I', data_len)
    return ident + head


def create_payload(conf):
    payload = create_payload_data(conf)
    header = create_payload_header(len(payload))
    return header + payload


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


async def tx_v4(fd, conf):
    addr     = conf['core']['v4-addr']
    port     = int(conf['core']['v4-port'])
    interval = float(conf['core']['tx-interval'])
    while True:
        try:
            data = create_payload(conf)
            fd.sendto(data, (addr, port))
        except Exception as e:
            print(str(e))
        await asyncio.sleep(interval)


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


def update_db(conf, db, data):
    new_entry = False

    if "hna" not in data["payload"]:
        print("no HNA data in payload, ignoring it")
        return

    for entry in data["payload"]["hna"]:
        found = False
        prefix = "{}/{}".format(entry[0], entry[1])
        for db_entry in db["networks"]:
            if prefix == db_entry[0]:
                db_entry_update(db_entry, data, prefix)
                found = True
        if not found:
            db_entry_new(conf, db, data, prefix)
            new_entry = True

    if new_entry:
        ipc_trigger_update_routes(conf, db)


async def handle_packet(queue, conf, db):
    while True:
        entry = await queue.get()
        data = parse_payload(entry)
        if data:
            update_db(conf, db, data)


def ipc_send_request(conf, data = None):
    url = "http://{}:{}{}".format(conf["update-ipc"]["host"], conf["update-ipc"]["port"], conf["update-ipc"]["url"])
    user_agent_headers = { 'Content-type': 'application/json',
                           'Accept':       'application/json' }

    # just ignore any configured system proxy, we don't need
    # a proxy for localhost communication
    proxy_support = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_support)
    urllib.request.install_opener(opener)

    request = urllib.request.Request(url, data.encode('ascii'), user_agent_headers)
    try:
        server_response = urllib.request.urlopen(request).read()
    except urllib.error.HTTPError as e:
        print("Failed to reach the IPC server ({}): '{}'".format(url, e.reason))
        return
    except urllib.error.URLError as e:
        print("Failed to reach the IPC server ({}): '{}'".format(url, e.reason))
        return
    server_data = addict.Dict(json.loads(str(server_response, "utf-8")))
    if server_data.status != "ok":
        print(server_data)


def ipc_trigger_update_routes(conf, db):
    cmd = {}
    cmd["terminal"] = {}
    cmd["terminal"]["ip"] = conf["core"]["terminal-v4-addr"]
    cmd["terminal"]["bandwidth_max"] = "5000 bit/s"

    cmd["routes"] = []

    for db_entry in db["networks"]:
        prefix, prefix_len = db_entry[0].split("/")
        e = {}
        e["l2-proto"] = "IPv4"
        e["prefix"]     = prefix
        e["prefix-len"] = prefix_len
        cmd["routes"].append(e)

    cmd_json = json.dumps(cmd)
    ipc_send_request(conf, cmd_json)


async def ipc_regular_update(db, conf):
    while True:
        await asyncio.sleep(float(conf["update-ipc"]["max-update-interval"]))
        print("regular IPC update active")
        ipc_trigger_update_routes(conf, db)


def init_socket_v4_tx(ctx, addr_v4):
    pass


def init_socket_v4_rx(ctx, addr_v4):
    pass


def init_sockets_v4(ctx, addr_v4):
    init_socket_v4_tx(ctx, addr_v4)
    init_socket_v4_rx(ctx, addr_v4)


def init_sockets(ctx):
    for interface in ctx['conf']['core']['interfaces']:
        if "addr-v4" in interface:
            init_sockets_v4(ctx, interface["addr-v4"])
        #if "addr-v6" in interface:
        #    init_sockets_v6(ctx, interface["addr-v6"])


def ask_exit(signame, ctx):
    sys.stderr.write("\rreceived signal \"%s\": exit now, bye\n" % signame)
    ctx['loop'].stop()


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

    init_sockets(ctx)

    #  # RX functionality
    #  fd = init_v4_rx_fd(ctx)
    #  loop.add_reader(fd, functools.partial(cb_v4_rx, fd, ctx))

    #  # TX side
    #  fd = init_v4_tx_fd(ctx)
    #  asyncio.ensure_future(tx_v4(fd, ctx))

    #  # Outputter
    #  asyncio.ensure_future(handle_packet(queue, ctx))

    #  # we regulary transmit
    #  asyncio.ensure_future(ipc_regular_update(db, ctx))


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
