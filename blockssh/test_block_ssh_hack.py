from unittest.mock import Mock

import pytest
import yaml
import block_ssh_hack as block
import json


def setup_module():
    block.log = Mock()
    block.log.info = Mock()
    block.log.debug = Mock()

    with open("test_block_ssh_hack.yaml") as fd:
        block.PROCESS_CFG = yaml.safe_load(fd.read())


def test_failed_password():
    input_line = "Nov  1 11:41:59 kvasir sshd[58242]: Failed password for root from 200.73.138.19 port 55624 ssh2"
    patterns = block.build_regex_list(block.PROCESS_CFG['auth_expressions'])
    rv, details = block.check_log_line(input_line[16:].rstrip(), patterns)
    assert rv


def test_invalid_user():
    input_line =\
        "Nov  1 12:13:00 kvasir sshd[58362]: Failed password for invalid user pi from 2.34.166.62 port 34356 ssh2"
    patterns = block.build_regex_list(block.PROCESS_CFG['auth_expressions'])
    rv, details = block.check_log_line(input_line[16:].rstrip(), patterns)
    assert rv


def test_failed_none():
    input_line =\
        "Nov  1 11:59:52 kvasir sshd[58318]: Failed none for invalid user admin from 59.25.189.150 port 39177 ssh2"
    patterns = block.build_regex_list(block.PROCESS_CFG['auth_expressions'])
    rv, details = block.check_log_line(input_line[16:].rstrip(), patterns)
    assert rv


def test_disconnect_preauth():
    input_line = "Nov  1 12:38:01 kvasir sshd[58584]: Received disconnect from 61.177.173.14 port 31106:11:  [preauth]"
    patterns = block.build_regex_list(block.PROCESS_CFG['auth_expressions'])
    rv, details = block.check_log_line(input_line[16:].rstrip(), patterns)
    assert rv


def test_disconnect_byebye():
    input_line = \
        "Nov  1 12:14:28 kvasir sshd[58371]: Received disconnect from 205.214.74.6 port 40020:11: Bye Bye [preauth]"
    patterns = block.build_regex_list(block.PROCESS_CFG['auth_expressions'])
    rv, details = block.check_log_line(input_line[16:].rstrip(), patterns)
    assert rv


def test_kex_method_drop():
    input_line = \
        "Nov  1 01:56:04 kvasir sshd[54535]: Unable to negotiate with 141.98.10.210 port 45474: " \
        "no matching key exchange method found. Their offer: " \
        "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 [preauth]"
    patterns = block.build_regex_list(block.PROCESS_CFG['auth_expressions'])
    rv, details = block.check_log_line(input_line[16:].rstrip(), patterns)
    assert rv


def test_get_block_set_details():
    block.run_nft_command = Mock(return_value=(
        json.loads('[{"set":'
                   '{"family": "ip", "name": "SSH_DEVLOG_BLOCK", "table": "filter",'
                   '"type": "ipv4_addr", "handle": 15, "flags": ["timeout"]}'
                   '}]'),
        json.loads('{"metainfo": {"version": "0.9.8", "release_name": "E.D.S.", "json_schema_version": 1}}')))
    block.list_table_sets = Mock(return_value=['SSH_DEVLOG_BLOCK'])
    assert block.init_block_set() is None


def test_get_block_set_details_error():
    block.run_nft_command = Mock(return_value=(
        json.loads('[{"set":'
                   '{"family": "ip", "name": "SSH_DEV_LOG_BLOCK", "table": "filter",'
                   '"type": "ipv6_addr", "handle": 15, "flags": []}'
                   '}]'),
        json.loads('{"metainfo": {"version": "0.9.8", "release_name": "E.D.S.", "json_schema_version": 1}}')))
    block.list_table_sets = Mock(return_value=['SSH_DEV_LOG_BLOCK'])
    with pytest.raises(AssertionError) as ex:
        block.init_block_set()

    assert str(ex.value) == 'the set must be created to contain ipv4 addresses'

    block.run_nft_command = Mock(return_value=(
        json.loads('[{"set":'
                   '{"family": "inet", "name": "SSH_DEV_LOG_BLOCK", "table": "filter",'
                   '"type": "ipv4_addr", "handle": 15, "flags": ["timeout"]}'
                   '}]'),
        json.loads('{"metainfo": {"version": "0.9.8", "release_name": "E.D.S.", "json_schema_version": 1}}')))

    with pytest.raises(AssertionError) as ex:
        block.init_block_set()

    assert str(ex.value) == 'address family is not ipv4'

    block.run_nft_command = Mock(return_value=(
        json.loads('[{"set":'
                   '{"family": "ip", "name": "SSH_DEV_LOG_BLOCK", "table": "filter",'
                   '"type": "ipv4_addr", "handle": 15, "flags": []}'
                   '}]'),
        json.loads('{"metainfo": {"version": "0.9.8", "release_name": "E.D.S.", "json_schema_version": 1}}')))

    with pytest.raises(AssertionError) as ex:
        block.init_block_set()

    assert str(ex.value) == 'the set must be configured to allow timeouts'
