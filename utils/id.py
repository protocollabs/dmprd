import logging
import os
import pathlib
import socket
import uuid

XDG_CACHE_HOME = os.getenv('XDG_CACHE_HOME', os.path.expanduser('~/.cache'))
CACHE_PATH = pathlib.Path(XDG_CACHE_HOME) / 'dmprd' / 'uuid-id'

log = logging.getLogger()


def _calc_uuid():
    uuid_part = str(uuid.uuid1())
    host_part = socket.gethostname()
    return "{}-{}".format(uuid_part, host_part)


def _get_cached_id():
    if CACHE_PATH.exists():
        with CACHE_PATH.open('r') as f:
            id_ = f.read()
        log.debug("Use cached UUID {}".format(id_))
    else:
        id_ = _calc_uuid()
        log.debug(
            'Generated new UUID {}, save at {}'.format(id_, str(CACHE_PATH)))
        try:
            CACHE_PATH.mkdir(parents=True)
        except FileExistsError:
            pass
        with CACHE_PATH.open('w') as f:
            f.write(id_)

    return id_


def check_and_patch_id(conf):
    if 'id' in conf['core']:
        id_no = conf['core']['id']
        log.info("ID in configuration file: {}".format(id_no))
        return
    # no id specified, use UUID
    id_no = _get_cached_id()
    log.info("ID is UUID: {}".format(id_no))
    conf['core']['id'] = id_no
