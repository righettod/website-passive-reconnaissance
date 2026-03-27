"""
Provider to retrieve proxy information from ProxyNova.
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class ProxyNovaComb(OSINTProvider):
    def __init__(self, domain: str):
        super().__init__(name="ProxyNovaComb", target_ip_or_domain=domain)

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://api.proxynova.com/comb?query={self.target_ip_or_domain}&start=0&limit=100"
        response = httpx.get(url=service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        information_lines = {"PROXIES": []}
        if results.get("count", 0) > 0:
            for line in results.get("lines", []):
                information_lines["PROXIES"].append(line)
        else:
            information_lines["PROXIES"].append("No proxy information found.")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Proxy information")
