"""
Provider to search for mobile applications (iOS and Android) associated with a domain.
"""

import re

import httpx
import tldextract

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT, MOBILE_APP_STORE_COUNTRY_STORE_CODE, USER_AGENT


class MobileAppStores(OSINTProvider):
    def __init__(self, target_domain: str, country_code: str = MOBILE_APP_STORE_COUNTRY_STORE_CODE):
        super().__init__(name="MobileAppStores", target_ip_or_domain=target_domain)
        self.country_code = country_code

    def use_api_key(self) -> bool:
        return False

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        information_lines = {"IOS": [], "ANDROID": []}
        request_headers = {"User-Agent": USER_AGENT}
        domain_infos = tldextract.extract(self.target_ip_or_domain)
        base_domain = f"{domain_infos.domain}.{domain_infos.suffix}"
        base_domain_name = f"{domain_infos.domain}"
        # 1. iOS platform (App Store)
        try:
            # See https://performance-partners.apple.com/search-api
            service_url = f"https://itunes.apple.com/search?term={base_domain_name}&entity=software&country={self.country_code}"
            response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
            response.raise_for_status()
            results = response.json()
            found_ios = False
            for entry in results.get("results", []):
                if "sellerUrl" in entry and base_domain.lower() in entry["sellerUrl"].lower():
                    information_lines["IOS"].append(f"iOS app found with TrackName '{entry['trackName']}' and BundleId '{entry['bundleId']}'.")
                    found_ios = True
            if not found_ios:
                information_lines["IOS"].append("No iOS app found.")
        except Exception as e:
            information_lines["IOS"].append(f"Error during iOS search: {str(e)}")

        # 2. Android platform (Google Play)
        try:
            service_url = f"https://play.google.com/store/search?q={base_domain_name}&c=apps&hl=en&gl={self.country_code}"
            response = httpx.get(service_url, headers=request_headers, timeout=req_timeout)
            response.raise_for_status()
            results = response.text
            android_bundle_regex = f"id=({domain_infos.suffix}\\.{domain_infos.domain}\\.[a-z0-9A-Z\\.\\-_]+)"
            bundles = re.findall(android_bundle_regex, results)
            if bundles:
                for bundle in sorted(list(set(bundles))):
                    information_lines["ANDROID"].append(f"Android app found with PackageId '{bundle}'.")
            else:
                information_lines["ANDROID"].append("No Android app found.")
        except Exception as e:
            information_lines["ANDROID"].append(f"Error during Android search: {str(e)}")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Mobile apps on official stores")
