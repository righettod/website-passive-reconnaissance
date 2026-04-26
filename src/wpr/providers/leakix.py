"""
Provider to retrieve information from LeakIX.
See https://files.leakix.net/p/api
"""

import re

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class Leakix(OSINTProvider):
    def __init__(self, api_key: str, field_type: str, field_value: str):
        # LeakIX uses 2 differents endpoints for DOMAIN and IP
        # So we use 2 fields to centralize call in a single service
        # We store them as target_ip_or_domain is not directly applicable.
        # We use a placeholder for target_ip_or_domain for consistency with the base class.
        super().__init__(name="Leakix", target_ip_or_domain=f"{field_type}:{field_value}")
        self.field_type = field_type
        self.field_value = field_value
        self.api_key = api_key

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json", "api-key": self.api_key}
        service_url = f"https://leakix.net/{self.field_type}/{self.field_value}"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        information_lines = {"LEAKS": []}
        if results["Leaks"] is not None:
            for leak in results["Leaks"]:
                for event in leak["events"]:
                    summary = event["summary"]
                    summary = re.sub(r"[\r\n\t]", "", summary)
                    data = f"{event['host']} ({event['ip']}) on {event['time'].split('T')[0]} => {summary}"
                    information_lines["LEAKS"].append(data)
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Leaked files for domain and IP addresses")
