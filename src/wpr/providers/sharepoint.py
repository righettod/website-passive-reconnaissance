"""
Provider to verify if the domain have SharePoint instances on "sharepoint.com"
via the existence of an instance on the subdomain "[domain-no-tld].sharepoint.com".
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class SharePoint(OSINTProvider):
    def __init__(self, domain: str):
        super().__init__(name="SharePoint", target_ip_or_domain=domain)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        suffix_prefix_collection = ["", "group", "dev", "test", "prod", "prd", "staging", "qa", "uat", "sandbox", "int"]
        suffix_prefix_separator_collection = ["", "-"]
        data_type = "SharePoint instances"
        request_headers = {"User-Agent": USER_AGENT}
        information_lines = {"INSTANCES": []}
        instance_url_tpl = "https://%s.sharepoint.com/"
        # Create the collection of subdomains to test
        subdomains = []
        for suffix_prefix in suffix_prefix_collection:
            for suffix_prefix_separator in suffix_prefix_separator_collection:
                # Use as prefix
                subdomain = f"{suffix_prefix}{suffix_prefix_separator}{self.target_ip_or_domain}"
                subdomains.append(subdomain.strip())
                # Use as suffix
                subdomain = f"{self.target_ip_or_domain}{suffix_prefix_separator}{suffix_prefix}"
                subdomains.append(subdomain.strip())
        subdomains = list(set(subdomains))
        subdomains.sort()
        # Test the different subdomains
        for subdomain in subdomains:
            try:
                # If the request succeed and the response code is different from 404 then the instance exists
                instance_url = instance_url_tpl % subdomain
                response = httpx.get(url=instance_url, headers=request_headers, timeout=req_timeout)
                status_code = response.status_code
                if status_code != 404:
                    information_lines["INSTANCES"].append(f"[HTTP {status_code}] {instance_url}")
            except httpx.ConnectError:
                pass
        if len(information_lines) == 0:
            information_lines["INSTANCES"].append("No instance found.")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type=data_type)
