import pytest
import yaml
import block_ssh_hack as block


@pytest.fixture()
def test_cfg():
    with open("test_block_ssh_hack.yaml") as fd:
        cfg = yaml.safe_load(fd.read())
    return cfg


def get_pattern_list(cfg):
    return block.build_regex_list(cfg.get('auth_expressions', []))


def test_failed_password(test_cfg):
    input_line = "Nov  1 11:41:59 kvasir sshd[58242]: Failed password for root from 200.73.138.19 port 55624 ssh2"
    patterns = get_pattern_list(test_cfg)
    rv, details = block.check_log_line(input_line, patterns)
    assert rv


def test_invalid_user(test_cfg):
    input_line =\
        "Nov  1 12:13:00 kvasir sshd[58362]: Failed password for invalid user pi from 2.34.166.62 port 34356 ssh2"
    patterns = get_pattern_list(test_cfg)
    rv, details = block.check_log_line(input_line, patterns)
    assert rv


def test_failed_none(test_cfg):
    input_line =\
        "Nov  1 11:59:52 kvasir sshd[58318]: Failed none for invalid user admin from 59.25.189.150 port 39177 ssh2"
    patterns = get_pattern_list(test_cfg)
    rv, details = block.check_log_line(input_line, patterns)
    assert rv


def test_disconnect_preauth(test_cfg):
    input_line = "Nov  1 12:38:01 kvasir sshd[58584]: Received disconnect from 61.177.173.14 port 31106:11:  [preauth]"
    patterns = get_pattern_list(test_cfg)
    rv, details = block.check_log_line(input_line, patterns)
    assert rv


def test_disconnect_byebye(test_cfg):
    input_line = \
        "Nov  1 12:14:28 kvasir sshd[58371]: Received disconnect from 205.214.74.6 port 40020:11: Bye Bye [preauth]"
    patterns = get_pattern_list(test_cfg)
    rv, details = block.check_log_line(input_line, patterns)
    assert rv


def test_kex_method_drop(test_cfg):
    input_line = \
        "Nov  1 01:56:04 kvasir sshd[54535]: Unable to negotiate with 141.98.10.210 port 45474: " \
        "no matching key exchange method found. Their offer: " \
        "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 [preauth]"
    patterns = get_pattern_list(test_cfg)
    rv, details = block.check_log_line(input_line, patterns)
    assert rv
