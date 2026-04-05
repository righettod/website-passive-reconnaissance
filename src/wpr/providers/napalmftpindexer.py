"""
Provider to search for FTP servers via SearchFTPs.net.
See https://www.searchftps.net/
"""

import re

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class NapalmFtpIndexer(OSINTProvider):
    def __init__(self, domain: str):
        super().__init__(name="NapalmFtpIndexer", target_ip_or_domain=domain)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"}
        information_lines = {"FTP_INDEXES": []}
        service_url = "https://www.searchftps.net/"
        expected_response_marker = "showing results"
        regex_results_count = r"Showing\s+results\s+\d+\s+to\s+\d+\s+of\s+about\s+(\d+)"
        form_data = {"action": "result", "args": f"k={self.target_ip_or_domain}&t=and&o=date-desc&s=0"}
        response = httpx.post(url=service_url, headers=request_headers, data=form_data, timeout=req_timeout)
        response.raise_for_status()
        results = response.text
        if expected_response_marker not in results.lower():
            # Original code wrote to debug.tmp, here we add to information_lines
            information_lines["FTP_INDEXES"].append(f"Non-expected response received, marker '{expected_response_marker}' not found.")
            return OSINTProviderData(information_lines=information_lines)
        results_count_match = re.findall(regex_results_count, results, re.IGNORECASE | re.MULTILINE)
        if results_count_match and int(results_count_match[0]) > 0:
            information_lines["FTP_INDEXES"].append(f"{results_count_match[0]} entries present on the site.")
        else:
            return OSINTProviderData(information_lines=information_lines, description_of_data_type="FTP server entries")
