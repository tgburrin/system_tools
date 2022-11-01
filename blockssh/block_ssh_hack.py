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
from socket import AF_INET

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

    payload = json.loads(cmdres.stdout)['nftables']
    metadata = payload.pop(0)
    return payload, metadata


def get_current_block_list():
    nftable = PROCESS_CFG['nft_table']
    block_set = PROCESS_CFG['nft_auth_log_set']

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
        if setdetails.get('table') == PROCESS_CFG['nft_table']:
            rv.append(setdetails.get('name'))

    return rv


def init_block_set():
    table_sets = list_table_sets()


def build_regex_list(pattern_list):
    rv = [re.compile(p) for p in pattern_list]
    return rv


def check_log_line(log_line, pattern_list):
    rv = False
    details = {"hostname": None, "username": None, "ip": None}

    log_line = log_line[16:].rstrip()  # 15 char timestamp + 1 space
    for p in pattern_list:
        m = re.match(p, log_line)
        if m:
            match_parts = m.groupdict()
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
    nftable = PROCESS_CFG['nft_table']
    block_set = PROCESS_CFG['nft_auth_log_set']

    log.info(f"blocking {addr}")
    with nftables.main.NFTables(nfgen_family=AF_INET) as nft:
        nft.set_elems(
            "add",
            table=nftable,
            set=block_set,
            elements={addr},
        )
    return True


def process_log_lines(ifd, patterns):
    rv = []
    raw_line = ifd.readline()
    while raw_line != "":
        ts = raw_line[:15]
        line = raw_line[16:].rstrip()
        if line.startswith(MYHOST):  # this eliminates multiline syslog statements
            ismatch, addr_details = check_log_line(line, patterns)
            if ismatch:
                rv.append(addr_details)
    return rv


def process_messages(msgs):
    c = STATS_DB.cursor()

    blockips = set()
    for msg in msgs:
        if msg.get('ip') in blockips:
            continue

        c.execute("update ssh_drops_counter set block_count = block_count+1 where block_address = ?", (msg.get('ip'), ))
        if not c.rowcount:
            c.execute("insert or ignore into ssh_drops_counter values (?,1)", (msg.get('ip'), ))

        blockips.add(msg.get('ip'))

    c.close()
    STATS_DB.commit()
    for ip in blockips:
        block_ip(ip)


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
    args = parse_arguments()
    with open(args["config"]) as fd:
        PROCESS_CFG = yaml.safe_load(fd.read())

    if not PROCESS_CFG.get('db_path'):
        PROCESS_CFG['db_path'] = DEFAULT_DB_STATE

    if not PROCESS_CFG.get('auth_log'):
        PROCESS_CFG['auth_log'] = DEFAULT_AUTH_LOG

    if not PROCESS_CFG.get('nft_table') or not PROCESS_CFG.get('nft_auth_log_set'):
        raise Exception("An nnft_table and nft_auth_log_set must be specified")

    if not PROCESS_CFG.get('nft_duration_min'):
        PROCESS_CFG['nft_duration_min'] = DEFAULT_DURATION_MIN

    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    log = logging.getLogger()
    log.setLevel(logging.INFO)
    # log.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))

    log.info("Starting ssh blocking process in pid {}".format(os.getpid()))
    signal.signal(signal.SIGHUP, stop_running)
    signal.signal(signal.SIGINT, stop_running)
    signal.signal(signal.SIGTERM, stop_running)

    log.info(f"Opening state database {PROCESS_CFG.get('db_path')}")
    STATS_DB = sqlite3.connect(PROCESS_CFG.get('db_path'))
    STATS_DB.row_factory = dict_row

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
