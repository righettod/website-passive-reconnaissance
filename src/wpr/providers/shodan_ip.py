"""
Provider to perform IP information lookup via Shodan.
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class ShodanIP(OSINTProvider):
    def __init__(self, api_key: str, ip_or_domain: str):
        super().__init__(name="ShodanIP", target_ip_or_domain=ip_or_domain, api_key=api_key)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://api.shodan.io/shodan/host/{self.target_ip_or_domain}?key={self.api_key}&minify=true"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        data = response.json()
        information_lines = {"IP_INFOS": []}
        information_lines["IP_INFOS"].append(f"Last scan date = {data['last_update']}")
        information_lines["IP_INFOS"].append(f"ISP = {data['isp']}")
        information_lines["IP_INFOS"].append(f"Organization = {data['org']}")
        hostnames = " , ".join(data.get("hostnames", []))
        information_lines["IP_INFOS"].append(f"Hostnames = {hostnames}")
        ports = str(data.get("ports", []))
        information_lines["IP_INFOS"].append(f"Ports = {ports}")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="General information of IP addresses and domain")
