"""
Provider to perform certificate transparency log lookup via crt.sh.
"""

import time

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, MAX_CALL_TENTATIVES, RETRY_WAIT_DELAY, USER_AGENT


class CertificateTransparencyLog(OSINTProvider):
    def __init__(self, target_domain: str):
        super().__init__(name="CertificateTransparencyLog", target_ip_or_domain=target_domain)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://crt.sh/?q=%.{self.target_ip_or_domain}&output=json"
        results = {}
        # CRT.SH is highly instable so we use a retry approach
        tentative_count = 0
        while tentative_count < MAX_CALL_TENTATIVES:
            response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
            tentative_count += 1
            if response.status_code == 200:
                results = response.json()
                break
            if tentative_count >= MAX_CALL_TENTATIVES:
                response.raise_for_status()
            time.sleep(RETRY_WAIT_DELAY)
        information_lines = {"CERTIFICATES": []}
        unique_certs = set()
        for entry in results:
            cert_name = f"{entry['name_value']} ({entry['issuer_name']})"
            unique_certs.add(cert_name)
        for cert in sorted(list(unique_certs)):
            information_lines["CERTIFICATES"].append(cert)
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Referenced subdomains of the target domain")
