import argparse
import configparser
import time

import httpx
from rich.console import Console

from wpr.common import OSINTProvider, OSINTProviderData, get_main_domain_without_tld, perform_dns_lookup, print_data_gathering_progress, print_header, print_osint_data
from wpr.constants import DEFAULT_CALL_TIMEOUT, MOBILE_APP_STORE_COUNTRY_STORE_CODE, WPR_VERSION
from wpr.providers.certificatetransparencylog import CertificateTransparencyLog
from wpr.providers.dns import Dns
from wpr.providers.dnsdumpster import DnsDumpster
from wpr.providers.github import GitHub
from wpr.providers.google import Google
from wpr.providers.grayhatwarfare import GrayHatWarfare
from wpr.providers.hackertarget import HackerTarget
from wpr.providers.intelx import IntelX
from wpr.providers.leakix import Leakix
from wpr.providers.mobileappstores import MobileAppStores
from wpr.providers.napalmftpindexer import NapalmFtpIndexer
from wpr.providers.pgpusers import PgpUsers
from wpr.providers.proxynovacomb import ProxyNovaComb
from wpr.providers.qualys_sslscan import QualysSslScan
from wpr.providers.shodan_cpe_cve import ShodanCpeCve
from wpr.providers.shodan_ip import ShodanIP
from wpr.providers.softwareheritage import SoftwareHeritage
from wpr.providers.swaggerhub import SwaggerHub
from wpr.providers.threatminer import ThreatMiner
from wpr.providers.viewdns import ViewDNS
from wpr.providers.waybackmachine import WaybackMachine
from wpr.providers.whois import Whois


def handle_provider_call(provider: OSINTProvider, req_timeout: int) -> OSINTProviderData:
    try:
        provider_data = provider.call(req_timeout)
    except httpx.HTTPStatusError as e:
        information_lines = {"HTTP ERROR DETAILS": [f"HTTP error {e.response.status_code}: {e.response.text}"]}
        provider_data = OSINTProviderData(information_lines=information_lines, description_of_data_type="Http Error")
    except Exception as e:
        information_lines = {"ERROR DETAILS": [str(e)]}
        provider_data = OSINTProviderData(information_lines=information_lines, description_of_data_type="Generic Error")
    return provider_data


def gather_data(domain: str, name_server: str | None, req_timeout: int, api_keys: dict[str, str], mobile_app_store_country_code: str) -> list[tuple[OSINTProvider, OSINTProviderData]]:
    providers_data = []
    domain_without_tld = get_main_domain_without_tld(domain)
    # First extract IP addresses and aliases for the domain
    records = perform_dns_lookup(domain, ["A", "AAAA"], name_server)
    ips_v4 = records.get("A", [])
    ips_v6 = records.get("AAAA", [])
    ips_all = set(ips_v4 + ips_v6)
    # Add information for IP and ALIASES
    provider = Dns(domain, name_server)
    print_data_gathering_progress(provider)
    provider_data = provider.call(req_timeout)
    providers_data.append((provider, provider_data))
    # Call the providers depending on which source data they use and define the order
    ## WHOIS
    for ip in ips_all:
        provider = Whois(ip)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    ## SHODAN
    api_key = api_keys.get("shodan", None)
    if api_key is not None:
        for ip in ips_all:
            provider = ShodanIP(api_key, ip)
            print_data_gathering_progress(provider)
            provider_data = handle_provider_call(provider, req_timeout)
            providers_data.append((provider, provider_data))
        for ip in ips_all:
            provider = ShodanCpeCve(api_key, ip)
            print_data_gathering_progress(provider)
            provider_data = handle_provider_call(provider, req_timeout)
            providers_data.append((provider, provider_data))
    ## HACKERTARGET
    for ip in ips_v4:
        provider = HackerTarget(ip)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    ## VIEWDNS
    api_key = api_keys.get("viewdns", None)
    if api_key is not None:
        for ip in ips_v4:
            provider = ViewDNS(api_key, ip)
            print_data_gathering_progress(provider)
            provider_data = handle_provider_call(provider, req_timeout)
            providers_data.append((provider, provider_data))
    ## THREATMINER
    for ip in ips_all:
        provider = ThreatMiner(ip)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    ## GOOGLE DORK
    for ip in ips_all:
        provider = Google(ip)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    provider = Google(domain)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## WAYBACKMACHINE
    provider = WaybackMachine(domain)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## QUALYS
    for ip in ips_all:
        provider = QualysSslScan(domain, ip)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    ## CERTIFICATE-TRANSPARENCY
    provider = CertificateTransparencyLog(domain)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## INTELX
    api_key = api_keys.get("intelx", None)
    if api_key is not None:
        for ip in ips_all:
            provider = IntelX(api_key, ip)
            print_data_gathering_progress(provider)
            provider_data = handle_provider_call(provider, req_timeout)
            providers_data.append((provider, provider_data))
        provider = IntelX(api_key, domain)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    ## GITHUB
    for ip in ips_all:
        provider = GitHub(ip)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    provider = GitHub(domain)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    provider = GitHub(domain_without_tld)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## SOFTWAREHERITAGE
    for ip in ips_all:
        provider = SoftwareHeritage(ip)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    provider = SoftwareHeritage(domain)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    provider = SoftwareHeritage(domain_without_tld)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## GRAYHATWARFARE
    api_key = api_keys.get("grayhatwarfare", None)
    if api_key is not None:
        provider = GrayHatWarfare(api_key, domain)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
        provider = GrayHatWarfare(api_key, domain_without_tld)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    ## GOOGLE PLAY + APPLE APP STORE
    provider = MobileAppStores(domain, mobile_app_store_country_code)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## OPENPGP KEYSERVER CIRCL.LU
    provider = PgpUsers(domain)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## LEAKIX
    api_key = api_keys.get("leakix", None)
    if api_key is not None:
        provider = Leakix(api_key, "domain", domain)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
        for ip in ips_v4:
            provider = Leakix(api_key, "host", ip)
            print_data_gathering_progress(provider)
            provider_data = handle_provider_call(provider, req_timeout)
            providers_data.append((provider, provider_data))
    ## NAPALM FTP INDEXER
    for ip in ips_v4:
        provider = NapalmFtpIndexer(ip)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    provider = NapalmFtpIndexer(domain)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    provider = NapalmFtpIndexer(domain_without_tld)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## PROXYNOVA COMB
    provider = ProxyNovaComb(domain)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    provider = ProxyNovaComb(domain_without_tld)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## SWAGGERHUB
    provider = SwaggerHub(domain)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    provider = SwaggerHub(domain_without_tld)
    print_data_gathering_progress(provider)
    provider_data = handle_provider_call(provider, req_timeout)
    providers_data.append((provider, provider_data))
    ## DNSDUMPSTER
    api_key = api_keys.get("dnsdumpster", None)
    if api_key is not None:
        provider = DnsDumpster(api_key, domain)
        print_data_gathering_progress(provider)
        provider_data = handle_provider_call(provider, req_timeout)
        providers_data.append((provider, provider_data))
    # Reset the progress indicator
    print_data_gathering_progress(provider, is_end=True)
    return providers_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    required_params = parser.add_argument_group("required arguments")
    required_params.add_argument("-d", action="store", dest="domain_name", help="Domain to analyse (ex: righettod.eu).", required=True)
    parser.add_argument("-a", action="store", dest="api_key_file", default=None, help="Configuration INI file with all API keys (ex: conf.ini).", required=False)
    parser.add_argument("-n", action="store", dest="name_server", default=None, help="Name server to use for the DNS query (ex: 8.8.8.8), default to the system defined one.", required=False)
    parser.add_argument("-t", action="store", dest="request_timeout", type=int, default=DEFAULT_CALL_TIMEOUT, help=f"Delay in seconds allowed for a HTTP request to reply before to fall in timeout (default to {DEFAULT_CALL_TIMEOUT} seconds).", required=False)
    parser.add_argument("-m", action="store", dest="mobile_app_store_country_code", default=MOBILE_APP_STORE_COUNTRY_STORE_CODE, help=f"Country code to define in which store mobile app will be searched (default to {MOBILE_APP_STORE_COUNTRY_STORE_CODE}).", required=False)
    args = parser.parse_args()
    api_key_config = configparser.ConfigParser()
    api_key_config["API_KEYS"] = {}
    if args.api_key_file is not None:
        api_key_config.read(args.api_key_file)
    default_request_timeout = DEFAULT_CALL_TIMEOUT
    if args.request_timeout is not None and args.request_timeout > 1:
        default_request_timeout = args.request_timeout
    default_name_server = None
    if args.name_server is not None:
        default_name_server = args.name_server
    default_mobile_app_store_country_store_code = MOBILE_APP_STORE_COUNTRY_STORE_CODE
    if args.mobile_app_store_country_code != MOBILE_APP_STORE_COUNTRY_STORE_CODE:
        default_mobile_app_store_country_store_code = args.mobile_app_store_country_code
    api_keys_dict = dict(api_key_config["API_KEYS"])
    print_header(["Execution context"])
    print(f"WPR version                   : {WPR_VERSION}")
    print(f"Target                        : {args.domain_name}")
    print(f"DNS name server specified     : {default_name_server}")
    print(f"API keys loaded               : {len(api_keys_dict)}")
    print(f"Mobile app store country used : {default_mobile_app_store_country_store_code}")
    print("")
    print_header(["Gather data from providers"])
    start_time = time.time()
    providers_data = gather_data(args.domain_name, default_name_server, default_request_timeout, api_keys_dict, default_mobile_app_store_country_store_code)
    delay = round(time.time() - start_time, 2)
    print("")
    for provider_data in providers_data:
        print_osint_data(provider_data)
        print("")
    # Final processing
    print("")
    Console().print(f"✅ Reconnaissance finished in [bright_green][bold]{delay}[/bold][/bright_green] seconds.")