"""
Provider to search for API definitions on SwaggerHub.
See https://app.swaggerhub.com/search
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class SwaggerHub(OSINTProvider):
    def __init__(self, domain: str):
        super().__init__(name="SwaggerHub", target_ip_or_domain=domain)

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://app.swaggerhub.com/apiproxy/specs?sort=BEST_MATCH&order=DESC&limit=25&specType=API&query={self.target_ip_or_domain}"
        response = httpx.get(url=service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        information_lines = {"APIS": []}
        if results.get("totalCount", 0) > 0:
            for api in results.get("apis", []):
                api_name = api.get("name", "N/A")
                api_url = "N/A"
                for prop in api.get("properties", []):
                    if prop.get("type", "").lower() == "swagger":
                        api_url = prop.get("url", "N/A")
                        break
                information_lines["APIS"].append(f"{api_name} => {api_url}")
        else:
            information_lines["APIS"].append("No APIs found on SwaggerHub.")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="API definitions")
