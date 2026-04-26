"""
Provider to perform CPE and CVE lookup via Shodan.
Note: Historical IP lookups require a membership or API subscription
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class ShodanCpeCve(OSINTProvider):
    def __init__(self, api_key: str, ip_or_domain: str):
        super().__init__(name="ShodanCpeCve", target_ip_or_domain=ip_or_domain, api_key=api_key)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT}
        service_url = f"https://api.shodan.io/shodan/host/{self.target_ip_or_domain}?key={self.api_key}&history=false"
        response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
        response.raise_for_status()
        data = response.json()
        information_lines = {"CPE_CVE": []}
        if "data" in data:
            # Extract the whole list of CPE and CVE detected by Shodan gathered by scan date
            cpe_cve_collection = {}
            for record in data["data"]:
                if "cpe" in record or "vulns" in record:
                    timestamp = record["timestamp"]
                    if timestamp not in cpe_cve_collection:
                        cpe_cve_collection[timestamp] = {"CPE": [], "CVE": []}
                    if "cpe" in record:
                        cpe_cve_collection[timestamp]["CPE"].extend(record["cpe"])
                    if "vulns" in record and len(record["vulns"]) > 0:
                        cves = []
                        vulns = record["vulns"]
                        for vuln_id in vulns:
                            summary = vulns[vuln_id].get("summary", "")
                            if len(summary) > 100:
                                summary = summary[:100] + "..."
                            cvss = vulns[vuln_id].get("cvss", "N/A")
                            cves.append(f"CVSS {cvss} - {vuln_id} - {summary}")
                        cves.sort(reverse=True)  # Highest CVSS score on top
                        cpe_cve_collection[timestamp]["CVE"].extend(cves)
            # Extract interesting infos by showing detected CPE with their associated CVE
            cpe_already_extracted = set()
            cve_already_extracted = set()
            for timestamp, record in cpe_cve_collection.items():
                scan_date_header_added = False
                for cpe in record["CPE"]:
                    if cpe not in cpe_already_extracted:
                        if not scan_date_header_added:
                            information_lines["CPE_CVE"].append(f"Scan date {timestamp}:")
                            scan_date_header_added = True
                        information_lines["CPE_CVE"].append(f"Detected software: '{cpe}'")
                        cpe_already_extracted.add(cpe)
                for cve in record["CVE"]:
                    if cve not in cve_already_extracted:
                        if not scan_date_header_added:
                            information_lines["CPE_CVE"].append(f"Scan date {timestamp}:")
                            scan_date_header_added = True
                        information_lines["CPE_CVE"].append(f"Detected CVE: {cve}")
                        cve_already_extracted.add(cve)
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="CPE/CVE information of the IP addresses")
