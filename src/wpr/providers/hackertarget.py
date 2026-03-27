"""
Provider to perform reverse IP lookup via HackerTarget.
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class HackerTarget(OSINTProvider):
    def __init__(self, ip_or_domain: str):
        super().__init__(name="HackerTarget", target_ip_or_domain=ip_or_domain)

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        vhosts = set()
        information_lines = {"VHOSTS": []}
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://api.hackertarget.com/reverseiplookup/?q={self.target_ip_or_domain}"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        for line in response.text.splitlines():
            if line.strip() and line.strip() != self.target_ip_or_domain:
                vhosts.add(line.strip())
        for vhost in sorted(list(vhosts)):
            information_lines["VHOSTS"].append(vhost)

        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Current hosts shared by IP address (active DNS)")
