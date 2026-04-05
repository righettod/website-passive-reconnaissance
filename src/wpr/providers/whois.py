"""
Provider to retrieve information about the owner of an IP address via Whois.
"""

from wpr.common import OSINTProvider, OSINTProviderData, get_whois_info
from wpr.constants import DEFAULT_CALL_TIMEOUT


class Whois(OSINTProvider):
    def __init__(self, target_domain: str):
        super().__init__(name="Dns", target_ip_or_domain=target_domain)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        infos = get_whois_info(self.target_ip_or_domain)
        information_lines = {"INFOS": infos["PARSED"]}
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="IP owner information")
