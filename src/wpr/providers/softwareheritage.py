"""
Provider to perform search in Software Heritage archive.
See https://archive.softwareheritage.org/api
"""

import datetime

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class SoftwareHeritage(OSINTProvider):
    def __init__(self, ip_or_domain: str):
        super().__init__(name="SoftwareHeritage", target_ip_or_domain=ip_or_domain)

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://archive.softwareheritage.org/api/1/origin/search/{self.target_ip_or_domain}/?limit=1000&with_visit=true"
        # Note: Original code mentioned a long timeout might be needed (up to 4 minutes),
        # but used DEFAULT_CALL_TIMEOUT. We'll use the provided req_timeout.
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        information_lines = {"DATA": [], "LIMIT": []}
        remaining = response.headers.get("X-RateLimit-Remaining", "NA")
        reset_time = response.headers.get("X-RateLimit-Reset")
        if reset_time:
            next_reset = datetime.datetime.fromtimestamp(int(reset_time))
            information_lines["LIMIT"].append(f"{remaining} call(s) can still be performed (reset at {next_reset})")
        else:
            information_lines["LIMIT"].append(f"{remaining} call(s) can still be performed")
        for entry in results:
            information_lines["DATA"].append(entry["url"])
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Source code repositories references")
