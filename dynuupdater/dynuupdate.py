#!/usr/bin/env python3

import time
import datetime
import json
import signal
import sys
import argparse
import yaml
import logging.handlers
from typing import NoReturn, Optional, Type

from urllib.request import Request, urlopen
from urllib.error import HTTPError

from netifaces import AF_INET, AF_INET6
import netifaces

# https://www.dynu.com/Support/API#/
DEFAULT_POLL_PERIOD = 900


class DynDomainName:
    dynu_domain_id: Optional[int]
    domain_name: str
    node_name: Optional[str]
    is_subdomain: bool
    ipv4_addr: Optional[str]
    ipv4_addr_id: Optional[int]
    ipv6_addr: Optional[str]
    ipv6_addr_id: Optional[int]

    def __init__(self, domain_name: str, node_name: Optional[str] = None):
        self.domain_name = domain_name
        self.node_name = node_name

        self.dynu_domain_id = None
        self.ipv4_addr = None
        self.ipv4_addr_id = None
        self.ipv6_addr = None
        self.ipv6_addr_id = None

        if node_name:
            self.is_subdomain = True
        else:
            self.is_subdomain = False

    @property
    def domain_id(self) -> int:
        return self.dynu_domain_id

    @domain_id.setter
    def domain_id(self, dom_id: int):
        if type(dom_id) != int:
            raise ValueError(f"Domain Id must be an int; {dom_id} provided")
        self.dynu_domain_id = dom_id

    @property
    def ipv4_address(self) -> str:
        return self.ipv4_addr

    @ipv4_address.setter
    def ipv4_address(self, addr: Optional[str]):
        # Validation?
        if addr is None and self.is_subdomain:
            self.ipv4_addr_id = None
        self.ipv4_addr = addr

    @property
    def ipv6_address(self) -> str:
        return self.ipv6_addr

    @ipv6_address.setter
    def ipv6_address(self, addr: Optional[str]):
        # Validation?
        if addr is None and self.is_subdomain:
            self.ipv6_addr_id = None
        self.ipv6_addr = addr

    @property
    def full_name(self) -> str:
        if self.node_name:
            return ".".join([self.node_name, self.domain_name])
        else:
            return self.domain_name

    def get_address_list(self) -> set:
        rv = set()
        if self.ipv4_addr:
            rv.add((self.ipv4_addr, 'A'))
        if self.ipv6_addr:
            rv.add((self.ipv6_addr, 'AAAA'))
        return rv

    def get_address_id_list(self) -> set:
        rv = set()
        if self.ipv4_addr_id:
            rv.add(self.ipv4_addr_id)
        if self.ipv6_addr_id:
            rv.add(self.ipv6_addr_id)
        return rv


class DynuClient:
    hostname = "api.dynu.com"
    url = "/v2"
    url_base = f"https://{hostname}{url}"

    def __init__(self, api_token: str):
        self.api_token = api_token
        self.root_id_cache = {}

        self.logger = logging.getLogger()
        # self.logger.setLevel(logging.DEBUG)

    def get_root_domain_id(self, hostname: str) -> str:
        if self.root_id_cache.get(hostname):
            return self.root_id_cache.get(hostname)

        self.logger.debug(f"Getting id for hostname {hostname}")

        req = Request(f"{self.url_base}/dns/getroot/{hostname}")
        req.add_header('accept', 'application/json')
        req.add_header('API-Key', self.api_token)

        try:
            resp = urlopen(req)
            payload = resp.read().decode()
            self.logger.debug(f"{resp.status}: {payload}")
            rec = json.loads(payload)
            self.root_id_cache[hostname] = rec.get('id')
            return rec.get('id')
        except HTTPError as e:
            if e.code == 501:
                raise HTTPError(e.url, e.code,
                                msg=f"domain {hostname} not found: {e.reason}",
                                hdrs=e.headers, fp=e.fp)
            else:
                raise e

    def get_root_domain_record(self, domain_id: int) -> Optional[dict]:
        req = Request(f"{self.url_base}/dns/{domain_id}",
                      method="GET")
        req.add_header('accept', 'application/json')
        req.add_header('API-Key', self.api_token)
        try:
            resp = urlopen(req)
            return json.loads(resp.read().decode())
        except HTTPError as e:
            self.logger.warning(str(e))
            self.logger.warning(e.reason)

    def update_root_domain_record(self,
                                  domain: Type[DynDomainName]) -> NoReturn:
        update = {
            "name": domain.domain_name,
            "ipv4": False,
            "ipv6": False
        }
        if domain.ipv4_addr:
            update.update({"ipv4Address": domain.ipv4_addr, "ipv4": True})
        if domain.ipv6_addr:
            update.update({"ipv6Address": domain.ipv6_addr, "ipv6": True})

        self._maintain_root_domain_record(domain.domain_id, update)

    def _maintain_root_domain_record(self,
                                     domain_id: int, update_rec: dict) -> bool:
        rv = False
        self.logger.debug(f"request:\n{json.dumps(update_rec, indent=4)}")
        req = Request(f"{self.url_base}/dns/{domain_id}",
                      method="POST",
                      data=json.dumps(update_rec).encode())
        req.add_header('accept', 'application/json')
        req.add_header('API-Key', self.api_token)
        try:
            resp = urlopen(req)
            self.logger.debug(resp.read().decode())
            rv = True
        except HTTPError as e:
            self.logger.warning(str(e))
            self.logger.warning(e.reason)

        return rv

    def get_node_domain_records(self,
                                domain_id: int,
                                node_name: str) -> list[dict[str, str]]:
        rv = []
        req = Request(f"{self.url_base}/dns/{domain_id}/record", method="GET")
        req.add_header('accept', 'application/json')
        req.add_header('API-Key', self.api_token)

        try:
            resp = urlopen(req)
            rec = json.loads(resp.read().decode())
            for dns in rec.get('dnsRecords', []):
                if dns.get("nodeName") == node_name and \
                        dns.get('recordType') in ['A', 'AAAA']:
                    if dns.get('recordType') == 'A':
                        address = dns.get('ipv4Address')
                    elif dns.get('recordType') == 'AAAA':
                        address = dns.get('ipv6Address')
                    else:
                        continue

                    rv.append({"nodeName": dns.get("nodeName"),
                               "id": dns.get("id"),
                               "recordType": dns.get("recordType"),
                               "address":  address})

        except HTTPError as e:
            self.logger.warning(str(e))
            self.logger.warning(e.reason)

        return rv

    def add_node_domain_records(self, domain: Type[DynDomainName]) -> NoReturn:
        # this is one of the methods that 'knows' the other object
        if not domain.domain_id:
            raise AttributeError("Invallid domain id provided")
        if not domain.node_name:
            raise AttributeError(
                "Invalid domain object: nodename required for operation")

        if domain.ipv4_addr:
            update = {
                "nodeName": domain.node_name,
                "state": True,
                "recordType": "A",
                "ipv4Address": domain.ipv4_addr,
            }
            domain.ipv4_addr_id = self._add_node_domain_record(
                                    domain.domain_id,
                                    domain.ipv4_addr_id,
                                    update)

        if domain.ipv6_addr:
            update = {
                "nodeName": domain.node_name,
                "state": True,
                "recordType": "AAAA",
                "ipv6Address": domain.ipv6_addr,
            }
            domain.ipv6_addr_id = self._add_node_domain_record(
                                    domain.domain_id,
                                    domain.ipv6_addr_id,
                                    update)

    def _add_node_domain_record(self,
                                domain_id: int,
                                node_id: Optional[int],
                                update_rec: dict) -> int:
        req_url = f"{self.url_base}/dns/{domain_id}/record"
        if node_id:
            req_url += f"/{node_id}"

        self.logger.debug(f"request:\n{json.dumps(update_rec, indent=4)}")

        req = Request(req_url,
                      method="POST",
                      data=json.dumps(update_rec).encode())
        req.add_header('accept', 'application/json')
        req.add_header('API-Key', self.api_token)

        try:
            resp = urlopen(req)
            body = resp.read().decode()
            payload = json.loads(body)
            self.logger.debug(body)
            return payload.get('id')
        except HTTPError as e:
            self.logger.warning(str(e))
            self.logger.warning(e.reason)
        return node_id

    def remove_node_domain_record(self, domain_id: int, node_id: int) -> bool:
        rv = False
        req = Request(f"{self.url_base}/dns/{domain_id}/record/{node_id}",
                      method="DELETE")
        req.add_header('accept', 'application/json')
        req.add_header('API-Key', self.api_token)
        try:
            resp = urlopen(req)
            self.logger.debug(resp.read().decode())
            rv = True
        except HTTPError as e:
            self.logger.warning(str(e))
            self.logger.warning(e.reason)
        return rv


def parse_arguments() -> dict:
    parser = argparse.ArgumentParser(
        description="A script for synchronizing interface ips with dynu.net"
    )

    parser.add_argument(
        "-c",
        "--config",
        dest="config",
        type=str,
        required=False,
        default="/etc/default/dynu_update.yaml",
        help="The process configuration file"
    )

    return vars(parser.parse_args())


def get_interface_details(inet_interface: str,
                          address_families: list[str]) -> dict[str, str]:
    record = {}

    if "ipv4" in address_families:
        for iface in netifaces.ifaddresses(inet_interface)[AF_INET]:
            record.update({"ipv4": iface.get('addr')})

    if "ipv6" in address_families:
        if netifaces.ifaddresses(inet_interface).get(AF_INET6):
            for iface in netifaces.ifaddresses(inet_interface)[AF_INET6]:
                # net = iface.get('addr').split(':')[0]
                # i = int(net, 16)
                # if i == 65152 or (64512 <= i <= 64768):
                #     continue

                # if there is an interface, split it off of the address
                record.update({"ipv6": iface.get('addr').split('%')[0]})

    return record


def stop_running(signum, frame):
    n = datetime.datetime.now().isoformat()
    lwr.info(f"{n}:Received signal, exiting")
    sys.exit(0)


if __name__ == "__main__":
    args = parse_arguments()
    with open(args["config"]) as fd:
        cfg = yaml.safe_load(fd.read())

    poll_period = cfg.get('poll_period', DEFAULT_POLL_PERIOD)

    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    lwr = logging.getLogger()
    lwr.setLevel(logging.INFO)
    # lwr.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))

    signal.signal(signal.SIGUSR1, stop_running)
    signal.signal(signal.SIGTERM, stop_running)

    dynu_client = DynuClient(cfg.get('access_token'))
    lwr.info("Starting dynu updater")

    domain_name_list = {}
    for target in cfg.get('targets'):
        for domain, sublist in target.items():
            for sub in sublist:
                full_name = domain
                if sub:
                    full_name = ".".join([sub, domain])

                try:
                    dynu_domain_id = dynu_client.get_root_domain_id(domain)
                    if not domain_name_list.get(full_name):
                        if not sub:
                            d = DynDomainName(domain)
                        else:
                            d = DynDomainName(domain, sub)

                        domain_name_list[d.full_name] = d
                        domain_name_list[d.full_name].domain_id = \
                            dynu_domain_id
                    else:
                        d = domain_name_list.get(full_name)
                        d.domain_id = dynu_domain_id

                except Exception as ex:
                    # The "root" of the domain must be created
                    # in the UI through the signup
                    lwr.warning(f"Not maintaining {full_name}")
                    lwr.warning(str(ex))

    while True:
        ips = get_interface_details(cfg['interface_name'],
                                    cfg["address_familes"])
        for domain_name, dom_obj in domain_name_list.items():
            lwr.debug(f"Maintaining {domain_name} -> {dom_obj.domain_id}")

            dom_obj.ipv4_address = ips.get('ipv4')
            dom_obj.ipv6_address = ips.get('ipv6')

            if dom_obj.is_subdomain:
                current_records = dynu_client.get_node_domain_records(
                                    dom_obj.domain_id,
                                    dom_obj.node_name)
                current_state = {"ipv4": None, "ipv6": None}
                for rec in current_records:
                    # Clean out dead records
                    addr_type = (rec.get('address'), rec.get('recordType'))
                    if rec.get('id') not in dom_obj.get_address_id_list() and \
                            addr_type not in dom_obj.get_address_list():
                        dynu_client.remove_node_domain_record(
                            dom_obj.domain_id,
                            rec.get('id'))
                    elif addr_type in dom_obj.get_address_list():
                        lwr.debug(
                            "Found id for "
                            f"{rec.get('address')} / {rec.get('recordType')}")

                        if rec.get('recordType') == 'A' and \
                                not dom_obj.ipv4_addr_id and \
                                dom_obj.ipv4_addr == rec.get('address'):
                            dom_obj.ipv4_addr_id = rec.get('id')

                        elif rec.get('recordType') == 'A' and \
                                dom_obj.ipv4_addr_id and \
                                dom_obj.ipv4_addr_id != rec.get('id'):
                            dynu_client.remove_node_domain_record(
                                dom_obj.domain_id,
                                dom_obj.ipv4_addr_id)
                            dom_obj.ipv4_addr_id = rec.get('id')

                        elif rec.get('recordType') == 'AAAA' and \
                                not dom_obj.ipv6_addr_id and \
                                dom_obj.ipv6_addr == rec.get('address'):
                            dom_obj.ipv6_addr_id = rec.get('id')

                        elif rec.get('recordType') == 'AAAA' and \
                                dom_obj.ipv6_addr_id and \
                                dom_obj.ipv6_addr_id != rec.get('id'):
                            dynu_client.remove_node_domain_record(
                                dom_obj.domain_id,
                                dom_obj.ipv6_addr_id)
                            dom_obj.ipv6_addr_id = rec.get('id')

                        if rec.get('recordType') == 'A' and \
                                rec.get('id') == dom_obj.ipv4_addr_id:
                            current_state['ipv4'] = rec.get('address')
                        if rec.get('recordType') == 'AAAA' and \
                                rec.get('id') == dom_obj.ipv6_addr_id:
                            current_state['ipv6'] = rec.get('address')

                if dom_obj.ipv4_addr != current_state['ipv4'] or \
                        dom_obj.ipv6_addr != current_state['ipv6']:
                    lwr.info(f"updating ips for {dom_obj.full_name}")
                    lwr.info(f"\t{current_state.get('ipv4')} -> "
                             f"{dom_obj.ipv4_addr}")
                    lwr.info(f"\t{current_state.get('ipv6')} -> "
                             f"{dom_obj.ipv6_addr}")
                    dynu_client.add_node_domain_records(dom_obj)

            else:
                current_record = dynu_client.get_root_domain_record(
                                    dom_obj.domain_id)
                if dom_obj.ipv4_addr != current_record.get('ipv4Address') or \
                        dom_obj.ipv6_addr != current_record.get('ipv6Address'):
                    lwr.info(f"updating ips for {dom_obj.full_name}")
                    lwr.info(f"\t{current_record.get('ipv4Address')} -> "
                             f"{dom_obj.ipv4_addr}")
                    lwr.info(f"\t{current_record.get('ipv6Address')} -> "
                             f"{dom_obj.ipv6_addr}")
                    dynu_client.update_root_domain_record(dom_obj)

        lwr.info(f"Sleeping for {poll_period}s...")
        time.sleep(poll_period)
