"""
Provider to perform passive shared hosts lookup via ThreatMiner.
See https://www.threatminer.org/api.php
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class ThreatMiner(OSINTProvider):
    def __init__(self, ip_or_domain: str):
        super().__init__(name="ThreatMiner", target_ip_or_domain=ip_or_domain)

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        vhosts = set()
        information_lines = {"VHOSTS": []}
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://api.threatminer.org/v2/host.php?q={self.target_ip_or_domain}&rt=2"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        if results.get("status_code") == "200" and "results" in results:
            for result in results["results"]:
                vhost = result["domain"].split(":")[0]
                vhosts.add(vhost)
        elif results.get("status_code") != "200":
            information_lines["VHOSTS"].append(f"ThreatMiner API returned status {results.get('status_code')}")
        for vhost in sorted(list(vhosts)):
            information_lines["VHOSTS"].append(vhost)
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Previous hosts shared by IP address (passive DNS)")
