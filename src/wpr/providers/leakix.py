"""
Provider to retrieve information from LeakIX.
See https://files.leakix.net/p/api
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class Leakix(OSINTProvider):
    def __init__(self, field_type: str, field_value: str):
        # LeakIX uses field_type and field_value in its query,
        # so we'll store them as target_ip_or_domain is not directly applicable.
        # We'll use a placeholder for target_ip_or_domain for consistency with the base class.
        super().__init__(name="Leakix", target_ip_or_domain=f"{field_type}:{field_value}")
        self.field_type = field_type
        self.field_value = field_value

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://files.leakix.net/json?q={self.field_type}:{self.field_value}"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        information_lines = {"LEAKS": []}
        status = results.get("status")
        if status == "success":
            for entry in results.get("data", []):
                last_changed = entry.get("last-modified", "N/A").split("T")[0]
                file_url = entry.get("url", "N/A")
                v = f"{last_changed}: {file_url}"
                information_lines["LEAKS"].append(v)
            information_lines["LEAKS"].sort()
        else:
            information_lines["LEAKS"].append(f"Status '{status}' received from LeakIX API.")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Leaked files for domain and IP addresses")
