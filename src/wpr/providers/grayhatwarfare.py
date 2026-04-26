"""
Provider to search for files and buckets in GrayHatWarfare.
See https://buckets.grayhatwarfare.com/api/v2/
"""

import httpx

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, USER_AGENT


class GrayHatWarfare(OSINTProvider):
    def __init__(self, api_key: str, domain: str):
        super().__init__(name="GrayHatWarfare", target_ip_or_domain=domain, api_key=api_key)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        request_headers = {"User-Agent": USER_AGENT, "Authorization": f"Bearer {self.api_key}"}
        information_lines = {"DATA": []}
        service_url_files = f"https://buckets.grayhatwarfare.com/api/v2/files?keywords={self.target_ip_or_domain}&limit=1000"
        service_url_buckets = f"https://buckets.grayhatwarfare.com/api/v2/buckets?keywords={self.target_ip_or_domain}&limit=1000"

        with httpx.Client(headers=request_headers, timeout=req_timeout) as client:
            # 1. Extract data for files
            response = client.get(service_url_files)
            response.raise_for_status()
            results = response.json()
            if "files" in results:
                for file in results["files"]:
                    information_lines["DATA"].append(f"[FILE  ]: {file['url']} ({file['size']} bytes)")

            # 2. Extract data for buckets
            response = client.get(service_url_buckets)
            response.raise_for_status()
            results = response.json()
            if "buckets" in results:
                for bucket in results["buckets"]:
                    if "container" in bucket:
                        information_lines["DATA"].append(f"[BUCKET]: '{bucket['bucket']}' in container '{bucket['container']}' ({bucket['fileCount']} files)")
                    else:
                        information_lines["DATA"].append(f"[BUCKET]: '{bucket['bucket']}' ({bucket['fileCount']} files)")

        information_lines["DATA"].sort()
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Files in AWS/AZURE buckets with reference to the domain")
