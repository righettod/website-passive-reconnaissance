"""
Provider to retrieve information from LeakIX.
See https://files.leakix.net/p/api
"""

import re

from leakix import Client

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT


class Leakix(OSINTProvider):
    def __init__(self, api_key: str, ip_or_domain: str):
        super().__init__(name="Leakix", target_ip_or_domain=ip_or_domain, api_key=api_key)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        client = Client(api_key=self.api_key)
        response = client.get_domain(self.target_ip_or_domain)
        results = response.json()
        information_lines = {"LEAKS": []}
        if "leaks" in results and results["leaks"] is not None:
            for leak in results["leaks"]:
                for event in leak["events"]:
                    summary = event["summary"]
                    data_type = event["event_source"]
                    summary = re.sub(r"[\r\n\t]", "", summary)
                    data = f"{event['host']} ({event['ip']}) on {event['time'].split('T')[0]} of {data_type} => {summary}\n"  # add an extra empty line as the content can be large
                    information_lines["LEAKS"].append(data)
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Leaked files for domain and IP addresses")
