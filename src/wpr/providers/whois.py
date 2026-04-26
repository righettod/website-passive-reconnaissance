"""
Provider to retrieve information about the owner of an IP address via Whois.
"""

import socket

import whoisit

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT


class Whois(OSINTProvider):
    def __init__(self, target_domain: str):
        super().__init__(name="Whois", target_ip_or_domain=target_domain)
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(DEFAULT_CALL_TIMEOUT)
        try:
            whoisit.bootstrap()
        finally:
            socket.setdefaulttimeout(old_timeout)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(req_timeout)
        try:
            result = whoisit.ip(self.target_ip_or_domain)
        finally:
            socket.setdefaulttimeout(old_timeout)
        infos = []
        desc = result["description"]
        infos.append(f"Range: {result['handle']}")
        infos.append(f"Name : {result['name']}")
        if len(desc) > 0:
            infos.append(f"Desc : {' '.join(desc)}")
        infos.append(f"Admin: {result['entities']['administrative'][0]['name']}")
        infos.append(f"Tech : {result['entities']['technical'][0]['name']}")
        infos.append(f"Abuse: {result['entities']['abuse'][0]['name']}")
        return OSINTProviderData(information_lines={"INFOS": infos}, description_of_data_type="IP owner information")
