"""
Provider to perform DNS lookup via DNSDumpster API.
See https://dnsdumpster.com/developer/
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class DnsDumpster(OSINTProvider):
    def __init__(self, api_key: str, domain: str):
        super().__init__(name="DnsDumpster", target_ip_or_domain=domain, api_key=api_key)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT, "X-API-Key": self.api_key}
        service_url = f"https://api.dnsdumpster.com/domain/{self.target_ip_or_domain}"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        information_lines = {"DNS_RECORDS": []}
        record_type_map = {"txt": "TXT", "mx": "MX", "ns": "NS"}
        for entry, data in results.items():
            if entry == "total_a_recs":
                continue
            name = record_type_map.get(entry, "HOST")
            if entry == "txt":
                for entry_info in data:
                    information_lines["DNS_RECORDS"].append(f"[{name:<6}]: Entry {entry_info}")
            else:
                for entry_info in data:
                    host_name = entry_info.get("host", "N/A")
                    if "ips" in entry_info:
                        for ip_info in entry_info["ips"]:
                            ip = ip_info.get("ip", "N/A")
                            ptr = ip_info.get("ptr", "N/A")
                            asn = ip_info.get("asn_name", "N/A")
                            information_lines["DNS_RECORDS"].append(f'[{name:<6}]: IP "{ip}" - Domain "{host_name}" - ReverseDNS "{ptr}" - AS "{asn}"')
                    else:
                        information_lines["DNS_RECORDS"].append(f'[{name:<6}]: Domain "{host_name}"')
        information_lines["DNS_RECORDS"].sort()
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Cartography information about the domain")
