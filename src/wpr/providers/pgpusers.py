"""
Provider to retrieve PGP users information from OpenPGP Key Server.
See https://openpgp.circl.lu
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class PgpUsers(OSINTProvider):
    def __init__(self, domain: str):
        super().__init__(name="PgpUsers", target_ip_or_domain=domain)

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://openpgp.circl.lu/pks/lookup?search={self.target_ip_or_domain}&options=mr&op=index"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        results = response.text
        information_lines = {"PGP_USERS": []}
        unique_users = set()
        for entry in results.splitlines():
            if entry.startswith("uid:"):
                # Extract the value after "uid:"
                user_info = entry[len("uid:") :].strip()
                if user_info:
                    unique_users.add(user_info)
        for user in sorted(list(unique_users)):
            information_lines["PGP_USERS"].append(user)
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="User entries for email domain")
