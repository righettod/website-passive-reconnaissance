"""
Provider to verify if the domain have Salesforce instances on "salesforce.com"
via the existence of an instance on the subdomain "[domain-no-tld].my.salesforce.com".
"""

from wpr.common import OSINTProvider, OSINTProviderData, perform_dns_lookup
from wpr.constants import DEFAULT_CALL_TIMEOUT


class Salesforce(OSINTProvider):
    def __init__(self, domain: str, name_server: str | None):
        super().__init__(name="Salesforce", target_ip_or_domain=domain)
        self.name_server = name_server

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        suffix_prefix_collection = ["", "group", "dev", "test", "prod", "prd", "staging", "qa", "uat", "sandbox", "int"]
        suffix_prefix_separator_collection = ["", "-", "."]
        data_type = "Salesforce instances"
        information_lines = {"INSTANCES": []}
        instance_domain_tpl = "%s.my.salesforce.com"
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
            # If CNAME records exists then the instance exists
            fqdn = instance_domain_tpl % subdomain
            records = perform_dns_lookup(fqdn, ["CNAME"], self.name_server, req_timeout)
            if len(records.get("CNAME", [])) > 0:
                information_lines["INSTANCES"].append(f"https://{fqdn}")
        if len(information_lines["INSTANCES"]) == 0:
            information_lines["INSTANCES"].append("No instance found.")
        return OSINTProviderData(information_lines=information_lines, description_of_data_type=data_type)
