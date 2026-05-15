"""
Provider to search for email addresses related to a domain.
See https://hunter.io/api
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class Hunter(OSINTProvider):
    def __init__(self, api_key: str, domain: str):
        super().__init__(name="Hunter", target_ip_or_domain=domain, api_key=api_key)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        information_lines = {"PATTERN": [], "EMAILS": []}
        service_url_domain = f"https://api.hunter.io/v2/domain-search?domain={self.target_ip_or_domain}&api_key={self.api_key}"

        with httpx.Client(headers=request_headers, timeout=req_timeout) as client:
            response = client.get(service_url_domain)
            response.raise_for_status()
            results = response.json()["data"]
            if results["pattern"] is not None:
                information_lines["PATTERN"].append(results["pattern"])
            for email_obj in results["emails"]:
                email_addr = email_obj["value"]
                email_sources = email_obj["sources"]
                email_source = ""
                if len(email_sources) > 0:
                    # Use only the first source
                    email_source_domain = email_sources[0]["domain"]
                    email_source_last_seen = email_sources[0]["last_seen_on"]
                    email_source_still_present = email_sources[0]["still_on_page"]
                    email_source = f' - Source domain "{email_source_domain}" - Last seen "{email_source_last_seen}" - Still present on source "{email_source_still_present}"'
                information_lines["EMAILS"].append(f'Address "{email_addr}" {email_source}'.strip())

        information_lines["EMAILS"].sort()
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Email addresses related to the domain")
