"""
Provider to perform SSL scan lookup via Qualys SSL Labs API.
See https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
"""

import datetime

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class QualysSslScan(OSINTProvider):
    def __init__(self, target_domain: str, target_ip: str):
        super().__init__(name="QualysSslScan", target_ip_or_domain=target_ip)
        self.target_domain = target_domain

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://api.ssllabs.com/api/v3/getEndpointData?host={self.target_domain}&s={self.target_ip_or_domain}&fromCache=on"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        data = response.json()
        information_lines = {"SSL_SCAN": []}
        if "errors" in data:
            error_msg = ""
            for error in data["errors"]:
                error_msg += error.get("message", "")
            information_lines["SSL_SCAN"].append(f"Errors: {error_msg}")
            return OSINTProviderData(information_lines=information_lines, description_of_data_type="SSL cached scan information")
        if data.get("statusMessage") == "Ready":
            if "ipAddress" in data:
                information_lines["SSL_SCAN"].append(f"IPAddress = {data['ipAddress']}")
            if "serverName" in data:
                information_lines["SSL_SCAN"].append(f"ServerName = {data['serverName']}")
            if "grade" in data:
                information_lines["SSL_SCAN"].append(f"Grade = {data['grade']}")
            if "details" in data:
                details = data["details"]
                if "hostStartTime" in details:
                    value = datetime.datetime.fromtimestamp(details["hostStartTime"] / 1000.0).strftime("%Y-%d-%mT%H:%M:%S")
                    information_lines["SSL_SCAN"].append(f"AssessmentStartingTime = {value}")
                for key in ["vulnBeast", "heartbleed", "poodle", "freak", "logjam"]:
                    if key in details:
                        information_lines["SSL_SCAN"].append(f"{key.upper()} = {details[key]}")
                if "drownVulnerable" in details:
                    information_lines["SSL_SCAN"].append(f"DROWN = {details['drownVulnerable']}")
                if "ticketbleed" in details:
                    information_lines["SSL_SCAN"].append(f"TICKETBLEED = {details['ticketbleed'] == 2}")
                if "bleichenbacher" in details:
                    is_robot = details["bleichenbacher"] in [2, 3]
                    information_lines["SSL_SCAN"].append(f"ROBOT = {is_robot}")
        else:
            status = data.get("statusMessage", "Unknown")
            information_lines["SSL_SCAN"].append(f"Scan status: {status}")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Information about TLS configuration and weakneses")
