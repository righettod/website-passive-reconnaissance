"""
Provider to perform reverse IP lookup via ViewDNS.
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class ViewDNS(OSINTProvider):
    def __init__(self, api_key: str, ip_or_domain: str):
        super().__init__(name="ViewDNS", target_ip_or_domain=ip_or_domain, api_key=api_key)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        vhosts = set()
        information_lines = {"VHOSTS": []}
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://api.viewdns.info/reverseip/?host={self.target_ip_or_domain}&apikey={self.api_key}&output=json"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        if "response" in results and "domains" in results["response"]:
            for result in results["response"]["domains"]:
                vhosts.add(result["name"])
        for vhost in sorted(list(vhosts)):
            information_lines["VHOSTS"].append(vhost)
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Current hosts shared by IP address (active DNS)")
