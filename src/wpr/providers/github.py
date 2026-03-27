"""
Provider to perform GitHub repository search for a given domain or IP.
See https://developer.github.com/v3/search/#search-repositories
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class GitHub(OSINTProvider):
    def __init__(self, ip_or_domain: str):
        super().__init__(name="GitHub", target_ip_or_domain=ip_or_domain)

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        term = f'"{self.target_ip_or_domain}"'
        params = {"q": f"size:>0 {term}", "sort": "updated", "order": "desc"}
        service_url = "https://api.github.com/search/repositories"
        response = httpx.get(service_url, headers=request_headers, params=params, timeout=req_timeout)
        response.raise_for_status()
        results = response.json()
        information_lines = {"REPOSITORIES": []}
        if "items" in results:
            for repo in results["items"]:
                html_url = repo["html_url"]
                is_fork = repo["fork"]
                forks = repo["forks"]
                watchers = repo["watchers"]
                information_lines["REPOSITORIES"].append(f"{html_url} (IsFork: {is_fork} - Forks: {forks} - Watchers: {watchers})")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Repositories with references to the IP addresses or the main domain in their content")
