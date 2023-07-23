#!/usr/bin/env python3

import time
import os.path
import subprocess
import signal
import sys
import argparse
import re
import sqlite3
import json
import logging.handlers

import yaml

DEFAULT_DB_STATE = "/var/lib/blockssh/blockssh.db"
DEFAULT_AUTH_LOG = "/var/log/auth.log"
DEFAULT_DURATION_MIN = 15

RUNNING = True
SCRIPT_NAME = os.path.splitext(os.path.basename(sys.argv[0]))[0]
MYHOST = os.uname()[1]
PROCESS_CFG = {}


def dict_row(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def run_nft_command(cmd):
    cmdres = subprocess.run(f"nft -aj {cmd}".split(), capture_output=True)
    if cmdres.returncode != 0:
        raise ValueError(f"Error: {cmdres.stderr}")

    payload = {}
    metadata = {}
    if cmdres.stdout != b'':
        payload = json.loads(cmdres.stdout)['nftables']
        metadata = payload.pop(0)

    return payload, metadata


def get_block_set_details():
    nftable = PROCESS_CFG['nf_table']
    block_set = PROCESS_CFG['nf_auth_log_set']
    payload, metadata = run_nft_command(f"list set inet {nftable} {block_set}")
    rv = payload[0].get('set')
    if 'elem' in rv:
        del rv['elem']
    return rv


def get_current_block_list():
    nftable = PROCESS_CFG['nf_table']
    block_set = PROCESS_CFG['nf_auth_log_set']

    payload, metadata = run_nft_command(f"list set inet {nftable} {block_set}")
    rv = []
    for ipelem in payload[0].get('set').get('elem'):
        rv.append((ipelem.get('elem', {}).get('val')))
    return rv


def list_table_sets():
    payload, metadata = run_nft_command("list sets inet")
    rv = []
    for setinfo in payload:
        setdetails = setinfo.get('set')
        if setdetails.get('table') == PROCESS_CFG['nf_table']:
            rv.append(setdetails.get('name'))

    return rv


def init_block_set():
    nf_set = PROCESS_CFG['nf_auth_log_set']
    nf_table = PROCESS_CFG['nf_table']
    table_sets = list_table_sets()
    if nf_set not in table_sets:
        payload, metadata = run_nft_command(
                f"add set inet {nf_table} {nf_set} {{ type ipv4_addr; flags dynamic, timeout;}}"
            )
    else:
        set_details = get_block_set_details()
        assert set_details.get('family') == 'inet', 'address family is not ipv4'
        assert set_details.get('type') == 'ipv4_addr', 'the set must be created to contain ipv4 addresses'
        assert 'timeout' in set_details.get('flags'), 'the set must be configured to allow timeouts'


def build_regex_list(pattern_list):
    rv = [re.compile(p) for p in pattern_list]
    return rv


def check_log_line(log_line, pattern_list):
    rv = False
    details = {"hostname": None, "username": None, "ip": None}
    for p in pattern_list:
        m = re.match(p, log_line)
        if m:
            log.debug(f"Log line {log_line} matches")
            match_parts = m.groupdict()
            log.debug(f"{match_parts}")
            if match_parts.get('HOSTNAME'):
                details['hostname'] = match_parts.get('HOSTNAME')
            if match_parts.get('USERNAME'):
                details['username'] = match_parts.get('USERNAME')

            if match_parts.get("IPADDRESS"):
                details['ip'] = match_parts.get("IPADDRESS")
                rv = True  # This will determine the success / failure of the match
                break
    return rv, details


def stop_running(signum, frame):
    global RUNNING
    RUNNING = False


def block_ip(addr):
    log.info(f"Adding {addr} to list of application blocks")
    nf_set = PROCESS_CFG['nf_auth_log_set']
    nf_table = PROCESS_CFG['nf_table']

    expr = f"{addr} timeout {PROCESS_CFG['nf_duration_min']}m"
    cmd = f"add element inet {nf_table} {nf_set} {{ {expr} }}"
    payload, metadata = run_nft_command(cmd)
    return True


def process_log_lines(ifd, patterns):
    rv = []
    raw_line = ifd.readline()
    while raw_line != "":
        # ts = raw_line[:15]
        # line = raw_line[16:].rstrip()
        (ts, line) = raw_line.split(maxsplit=1)
        if line.startswith(MYHOST):  # this eliminates multiline syslog statements
            ismatch, addr_details = check_log_line(line, patterns)
            if ismatch:
                log.debug(f"Adding {addr_details} from {line}")
                rv.append(addr_details)
        raw_line = ifd.readline()
    return rv


def process_messages(msgs):
    c = STATS_DB.cursor()
    updatesql = """update ssh_drops_counter set
        block_count = block_count+1,
        last_block_time = CURRENT_TIMESTAMP
    where block_address = ?"""

    insertsql = """insert or ignore into ssh_drops_counter (block_address) values (?)"""

    blockips = set()
    for msg in msgs:
        ip = msg.get('ip')
        if ip in blockips:
            continue

        c.execute(updatesql, (ip, ))
        if not c.rowcount:
            c.execute(insertsql, (ip, ))
        blockips.add(msg.get('ip'))
        block_ip(ip)

    c.close()
    STATS_DB.commit()


def create_stats_table():
    c = STATS_DB.cursor()

    table_def = """create table ssh_drops_counter (
    block_address text primary key,
    block_count integer not null default 1,
    last_block_time datetime not null default CURRENT_TIMESTAMP )"""

    res = c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    table_list = [row.get('name') for row in res]
    if 'ssh_drops_counter' not in table_list:
        c.execute(table_def)

    c.close()
    STATS_DB.commit()


def parse_arguments() -> dict:
    parser = argparse.ArgumentParser(
        description="A script for blocking failed ssh connections"
    )

    parser.add_argument(
        "-c",
        "--config",
        dest="config",
        type=str,
        required=False,
        default="/etc/default/block_ssh_hack.yaml",
        help="The process config file"
    )

    return vars(parser.parse_args())


if __name__ == "__main__":
    log_level = logging.INFO

    args = parse_arguments()
    with open(args["config"]) as fd:
        PROCESS_CFG = yaml.safe_load(fd.read())

    if not PROCESS_CFG.get('db_path'):
        PROCESS_CFG['db_path'] = DEFAULT_DB_STATE

    if not PROCESS_CFG.get('auth_log'):
        PROCESS_CFG['auth_log'] = DEFAULT_AUTH_LOG

    if not PROCESS_CFG.get('nf_table') or not PROCESS_CFG.get('nf_auth_log_set'):
        raise Exception("An nnf_table and nf_auth_log_set must be specified")

    if not PROCESS_CFG.get('nf_duration_min'):
        PROCESS_CFG['nf_duration_min'] = DEFAULT_DURATION_MIN

    if PROCESS_CFG.get('logging_level') == "DEBUG":
        log_level = logging.DEBUG

    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    log = logging.getLogger()
    log.setLevel(log_level)
    # log.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))

    log.info("Starting ssh blocking process in pid {}".format(os.getpid()))
    signal.signal(signal.SIGHUP, stop_running)
    signal.signal(signal.SIGINT, stop_running)
    signal.signal(signal.SIGTERM, stop_running)

    log.info(f"Opening state database {PROCESS_CFG.get('db_path')}")
    STATS_DB = sqlite3.connect(PROCESS_CFG.get('db_path'))
    STATS_DB.row_factory = dict_row

    create_stats_table()
    init_block_set()

    inode = os.stat(PROCESS_CFG['auth_log']).st_ino
    infile = open(PROCESS_CFG['auth_log'], 'r')
    infile.seek(0, 2)

    regex_patterns = build_regex_list(PROCESS_CFG['auth_expressions'])

    while RUNNING:
        i = os.stat(PROCESS_CFG['auth_log']).st_ino
        if inode != i:
            log.debug("Closing and re-opening log file")
            infile.close()
            infile = open(PROCESS_CFG['auth_log'], 'r')
            inode = i

        lm = process_log_lines(infile, regex_patterns)
        if lm:
            process_messages(lm)

        time.sleep(0.125)

    infile.close()
    STATS_DB.close()
