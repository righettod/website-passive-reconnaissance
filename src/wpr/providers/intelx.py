"""
Intelligence X free API have hits credtis depending on the service consumed
A new account must be created after consumed all credits
See https://intelx.io/account?tab=developer
"""

import json

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class IntelX(OSINTProvider):
    def __init__(self, api_key: str, ip_or_domain: str):
        super().__init__(name="IntelX", target_ip_or_domain=ip_or_domain, api_key=api_key)

    def get_additional_infos(self) -> str:
        return "Use the following URL from a browser: https://intelx.io/?s=[IP_OR_DOMAIN]"

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT, "x-key": self.api_key}
        payload = {"term": self.target_ip_or_domain, "buckets": [], "lookuplevel": 0, "maxresults": 100, "timeout": 0, "datefrom": "", "dateto": "", "sort": 4, "media": 0, "terminate": []}
        # First we must do a search
        service_url = "https://2.intelx.io/intelligent/search"
        response = httpx.post(service_url, json=json.dumps(payload), headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        # Then get the result for the search
        search_id = str(response.json()["id"])
        service_url += f"/result?id={search_id}"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        data = response.json()
        buckets = {}
        pasties = {}
        if "records" in data:
            for record in data["records"]:
                if "bucket" in record:
                    bucket_name = record["bucket"]
                    # Special processing for Pasties, we extract URL and added date...
                    if bucket_name.lower() == "pastes" and "keyvalues" in record:
                        for paste in record["keyvalues"]:
                            value = paste["value"]  # Contains the paste URL
                            pasties[value] = record["added"]
                    if bucket_name not in buckets:
                        buckets[bucket_name.lower()] = 0
                    buckets[bucket_name.lower()] += 1
        # Add the information
        information_lines = {"BUCKETS": [], "PASTIES": []}
        for bucket_name in buckets:
            information_lines["BUCKETS"].append(f"{buckets[bucket_name]} records for bucket {bucket_name}")
        for paste in pasties:
            information_lines["PASTIES"].append(f"Paste '{paste}' added on {pasties[paste]}")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Information about the IP addresses or the domain")
