"""
Provider to retrieve information from Wayback Machine.
See https://archive.org/help/wayback_api.php
"""

import datetime

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class WaybackMachine(OSINTProvider):
    def __init__(self, domain: str):
        super().__init__(name="WaybackMachine", target_ip_or_domain=domain)

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://archive.org/wayback/available?url={self.target_ip_or_domain}"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        information_lines = {"SNAPSHOTS": []}
        if "archived_snapshots" in results and "closest" in results["archived_snapshots"]:
            closest_snapshot = results["archived_snapshots"]["closest"]
            url = closest_snapshot.get("url")
            last_scan_date = "N/A"
            if "timestamp" in closest_snapshot:
                last_scan_date = datetime.datetime.strptime(closest_snapshot["timestamp"], "%Y%m%d%H%M%S").strftime("%d/%m/%Y at %H:%M:%S")
            if url:
                information_lines["SNAPSHOTS"].append(f"URL to access to the history: {url}")
            information_lines["SNAPSHOTS"].append(f"Most recent archived snapshot taken on {last_scan_date}.")
        else:
            information_lines["SNAPSHOTS"].append("No archived snapshots found.")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Internet Archive (Wayback Machine) information")
