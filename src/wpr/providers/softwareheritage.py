"""
Provider to perform search in Software Heritage archive.
See https://archive.softwareheritage.org/api
"""


import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT


class SoftwareHeritage(OSINTProvider):
    def __init__(self, ip_or_domain: str):
        super().__init__(name="SoftwareHeritage", target_ip_or_domain=ip_or_domain)

    def get_additional_infos(self) -> str:
        return "Use the following URL pattern to browse the archived data: https://archive.softwareheritage.org/browse/origin/directory/?origin_url=[ENTRY_URL]"

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        # Mocking a real browser was causing the anti bot to trigger so let the default User Agent
        request_headers = {"Accept": "application/json"}
        service_url = f"https://archive.softwareheritage.org/api/1/origin/search/{self.target_ip_or_domain}/?limit=1000&with_visit=true"
        # Note: Original code mentioned a long timeout might be needed (up to 4 minutes),
        # but used DEFAULT_CALL_TIMEOUT. We'll use the provided req_timeout.
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        # Check that the response is a JSON one because currently even the API face the anti bot wall
        if "making sure you&#39;re not a bot!" in response.text.lower():
            raise Exception("API still face the anti bot wall issue!")
        information_lines = {"DATA": []}
        results = response.json()
        for entry in results:
            information_lines["DATA"].append(entry["url"])
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Source code repositories references")
