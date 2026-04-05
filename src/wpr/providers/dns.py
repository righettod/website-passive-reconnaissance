"""
Provider to retrieve specific DNS record types.
"""

from wpr.common import OSINTProvider, OSINTProviderData, perform_dns_lookup
from wpr.constants import DEFAULT_CALL_TIMEOUT


class Dns(OSINTProvider):
    def __init__(self, target_domain: str, name_server: str | None):
        super().__init__(name="Dns", target_ip_or_domain=target_domain)
        self.name_server = name_server

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        information_lines = {}
        records = perform_dns_lookup(self.target_ip_or_domain, ["A", "AAAA", "CNAME"], self.name_server)
        for record_type, record_entries in records.items():
            information_lines[record_type] = record_entries
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="IP V4/V6 addresses and aliases")
