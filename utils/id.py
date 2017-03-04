import uuid
import os
import logging
import socket

XDG_CACHE_HOME = os.getenv('XDG_CACHE_HOME', os.path.expanduser('~/.cache'))

log = logging.getLogger()

def _calc_uuid():
    uuid_part = str(uuid.uuid1())
    host_part = socket.gethostname()
    return "{}-{}".format(uuid_part, host_part)

def _write_cache_id(file_path, id_no):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as fd:
        fd.write(id_no)

def _get_cached_id(ctx):
    file_path = os.path.join(XDG_CACHE_HOME, "dmprd", "uuid-id")
    try:
        with open(file_path, 'r') as fd:
            data = fd.read()
        log.debug("Use cache generatid UUID ({}, {})".format(data, file_path))
        return data
    except Exception as e:
        id_no = _calc_uuid()
        log.debug("New cache generated UUID ({}, {})".format(id_no, file_path))
        _write_cache_id(file_path, id_no)
        return id_no

def check_and_patch_id(ctx):
    if 'id' in ctx['conf']['core']:
        id_no = ctx['conf']['core']['id']
        log.info("ID in configuration file: {}".format(id_no))
        return
    # no id specified, use UUID
    id_no = _get_cached_id(ctx)
    log.info("ID is UUID: {}".format(id_no))
    ctx['conf']['core']['id'] = id_no

