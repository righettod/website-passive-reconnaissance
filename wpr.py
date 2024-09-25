# -*- coding: utf-8 -*-
"""
Script to automate, when possible, the passive reconnaissance performed a website prior to an assessment.
Also used to guide the reconnaissance phase by defining all steps (manual or automated).

See README.md file for API Key INI file example.
"""
import colorama
import argparse
import collections
import configparser
import dns.resolver
import requests
import time
import sys
import socket
import datetime
import json
import os
import tldextract
import git
import urllib.parse
import base64
import re
from termcolor import colored
from dns.resolver import NoAnswer
from dns.resolver import NoNameservers
from dns.resolver import NXDOMAIN
from requests.exceptions import ProxyError, RequestException
from googlesearch import search
from urllib.error import HTTPError
from tabulate import tabulate
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
MOBILE_APP_STORE_COUNTRY_STORE_CODE = "LU"  # Luxembourg
DEFAULT_CALL_TIMEOUT = 30
WAPPALYZER_MAX_MONTHS_RESULT_OLD = 6
INTERESTING_FILE_EXTENSIONS = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pps", "odp", "ods", "odt", "rtf",
                               "java", "cs", "vb", "py", "rb", "zip", "tar", "gz", "7z", "eml", "msg", "sql", "ini",
                               "xml", "back", "txt", "csv"]
# See issue https://github.com/righettod/website-passive-reconnaissance/issues/89
RCE_PRONE_PARAMETERS_DORK = "inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:& site:%s"


def get_bing_dork_results(dork, api_key, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # See https://azure.microsoft.com/en-us/try/cognitive-services/?api=search-api-v7
        # For API key including trial one
        search_url = "https://api.cognitive.microsoft.com/bing/v7.0/search"
        request_headers = {"Ocp-Apim-Subscription-Key": api_key, "User-Agent": USER_AGENT}
        params = {"q": dork, "textFormat": "HTML", "count": 50, "safeSearch": "Off"}
        response = requests.get(search_url, params=params, headers=request_headers, proxies=web_proxies, verify=(
            http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            if "webPages" in data:
                record_count = data["webPages"]["totalEstimatedMatches"]
                infos.append(f"Estimated records count: {record_count}")
                for result in data["webPages"]["value"]:
                    link = result["url"]
                    infos.append(f"Record found: {link}")
        else:
            url_encoded_dork = urllib.parse.quote(dork)
            infos.clear()
            infos.append(f"Bing respond 'HTTP Error {response.status_code}: {response.reason}' => Check your API key or use the Dork in a browser using the following url:")
            infos.append(f"https://www.bing.com/search?q={url_encoded_dork}")
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_google_dork_results(dork, http_proxy):
    try:
        infos = []
        try:
            # The module Google use urllib and it uses the environment
            # variable "http_proxy" to determine which HTTP proxy to use
            if http_proxy is not None:
                os.environ["http_proxy"] = http_proxy
            # Leverage the module Google to do the search via the dork
            # Cleanup any exisiting Google cookies jar file
            google_cookies_file = ".google-cookie"
            if os.path.exists(google_cookies_file):
                os.remove(google_cookies_file)
            # Issue the on Google.com
            search_results = search(
                dork, tld="com", num=100, stop=100, pause=2, user_agent=USER_AGENT)
            for result in search_results:
                infos.append(f"Record found: {result}")
            infos.sort()
        except HTTPError as err:
            if err.code == 429:
                url_encoded_dork = urllib.parse.quote(dork)
                infos.clear()
                infos.append("Google respond 'HTTP Error 429: Too Many Requests' => Use another IP address or use the Dork in a browser using the following url:")
                infos.append(f"https://www.google.com/search?q={url_encoded_dork}")
            else:
                raise
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_intelx_infos(ip_or_domain, api_key, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # Intelligence X free API have hits credtis depending on the service consumed
        # A new account must be created after consumed all credits
        # See https://intelx.io/account?tab=developer
        request_headers = {"User-Agent": USER_AGENT, "x-key": api_key}
        payload = {
            "term": ip_or_domain,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 100,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": 0,
            "terminate": []
        }
        # First we must do a search
        service_url = f"https://2.intelx.io/intelligent/search"
        response = requests.post(service_url, data=json.dumps(payload), headers=request_headers, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos.append(f"HTTP response code {response.status_code} received for the search!")
            return infos
        # Then get the result for the search
        search_id = str(response.json()["id"])
        service_url += f"/result?id={search_id}"
        response = requests.get(service_url, headers=request_headers, proxies=web_proxies, verify=(
            http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        # Count result by bucket
        if response.status_code != 200:
            infos.append(f"HTTP response code {response.status_code} received for the result of the search!")
            return infos
        data = response.json()
        buckets = {}
        pasties = {}
        if "records" in data:
            for record in data["records"]:
                if "bucket" in record:
                    bucket_name = record["bucket"]
                    # Special processing for Pasties, we extract URL and added date...
                    if bucket_name.lower() == "pastes" and "keyvalues" in record:
                        for paste in record["keyvalues"]:
                            value = paste["value"]  # Contains the paste URL
                            pasties[value] = record["added"]
                    if bucket_name not in buckets:
                        buckets[bucket_name.lower()] = 0
                    buckets[bucket_name.lower()] += 1
        # Add the information
        for bucket_name in buckets:
            infos.append(f"{buckets[bucket_name]} records for bucket {bucket_name}")
        for paste in pasties:
            infos.append(f"Paste '{paste}' added on {pasties[paste]}")
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def extract_infos_from_virus_total_response(http_response):
    try:
        infos = []
        if http_response.status_code != 200:
            if http_response.status_code != 204:
                infos.append(f"HTTP response code {http_response.status_code} received!")
            else:
                infos.append(f"Request rate limit exceeded: Wait one minute and re-run the script!")
        else:
            results = http_response.json()
            # From VT API doc regarding the "response_code" property:
            # If the item you searched for was not present in VirusTotal's dataset this result will be 0.
            # If the requested item is still queued for analysis it will be -2.
            # If the item was indeed present and it could be retrieved it will be 1.
            # See https://developers.virustotal.com/reference#api-responses
            rc = results["response_code"]
            msg = results["verbose_msg"]
            infos.append(f"Presence = {msg}")
            if rc == 1:
                urls_detected_count = 0
                urls_undetected_count = 0
                samples_detected_download_count = 0
                samples_undetected_download_count = 0
                if "detected_urls" in results:
                    urls_detected_count = len(results["detected_urls"])
                if "undetected_urls" in results:
                    urls_undetected_count = len(results["undetected_urls"])
                if "detected_downloaded_samples" in results:
                    samples_detected_download_count = len(results["detected_downloaded_samples"])
                if "undetected_downloaded_samples" in results:
                    samples_undetected_download_count = len(results["undetected_downloaded_samples"])
                infos.append(f"URLs at this IP address that have at least one detection on a URL scan = {urls_detected_count}")
                infos.append(f"URLs at this IP address with no detections on a URL scan = {urls_undetected_count}")
                infos.append(f"Files that have been downloaded from this IP address with at least one AV detection = {samples_detected_download_count}")
                infos.append(f"Files that have been downloaded from this IP address with zero AV detections = {samples_undetected_download_count}")
            elif rc == -2:
                infos.append(f"Pending analysis for this item.")
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_main_domain_without_tld(domain):
    domain_infos = tldextract.extract(domain)
    return domain_infos.domain


def configure_proxy(http_proxy):
    web_proxies = {}
    if http_proxy is not None:
        web_proxies["http"] = http_proxy
        web_proxies["https"] = http_proxy
    return web_proxies


def test_proxy_connectivity(http_proxy):
    msg = ""
    try:
        web_proxies = {"http": http_proxy, "https": http_proxy}
        service_url = "https://perdu.com/"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code == 200:
            msg = "Succeed"
        else:
            msg = f"Failed (HTTP response code = {response.status_code})"
    except ProxyError as e:
        msg = f"Failed ({str(e)})"
    return msg


def print_infos(info_list, prefix=""):
    if len(info_list) == 0:
        print(f"{prefix}No data found")
    else:
        for info in info_list:
            print(f"{prefix}{info}")


def print_infos_as_table(data):
    if len(data) == 1:
        print(f"  No data found")
    else:
        print(tabulate(data, headers="firstrow", tablefmt="github", numalign="left", stralign="left"))


def do_whois_request(ip, whois_server):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((whois_server, 43))
    s.send((ip + "\r\n").encode())
    response = b""
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    return response.decode("utf-8", "ignore")


def do_whois(ip):
    whois_org = ["arin", "lacnic", "afrinic", "ripe", "apnic"]
    whois_server_tpl = "whois.%s.net"
    # First try with ARIN
    whois_response = do_whois_request(ip, whois_server_tpl % "arin")
    for line in whois_response.splitlines():
        if line.strip().startswith("Ref:"):
            # IP block is not managed by ARIN so we call the provided org in the Ref link
            link = line[4:].strip(" ")
            org = link.split("/")[-1]
            if org.lower() in whois_org:
                whois_response = do_whois_request(ip, whois_server_tpl % org)
                break
    return whois_response


def get_ip_addresses(domain, name_server, record_types):
    ips = []
    resolver = dns.resolver.Resolver(configure=True)
    if name_server is not None:
        resolver.nameservers = [name_server]
    for record_type in record_types:
        try:
            answer = resolver.resolve(domain, record_type)
            for data in answer:
                ips.append(data.to_text())
        except NoAnswer:
            pass
        except NoNameservers:
            pass
        except NXDOMAIN:
            pass
    return ips


def get_cnames(domain, name_server):
    cnames = []
    resolver = dns.resolver.Resolver(configure=True)
    if name_server is not None:
        resolver.nameservers = [name_server]
    try:
        answer = resolver.resolve(domain, "CNAME")
        for data in answer:
            cnames.append(data.target.to_text())
    except NoAnswer:
        pass
    return cnames


def get_active_shared_hosts(ip, http_proxy, viewdns_api_key):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # HackerTarget API is limited of 50 queries per day
        # See https://hackertarget.com/ip-tools/
        service_url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos.append(f"HTTP response code {response.status_code} received!")
            return infos
        vhosts = response.text
        for vhost in vhosts.splitlines():
            if vhost != ip:
                infos.append(vhost)
        # See https://viewdns.info/api/
        if viewdns_api_key is not None:
            service_url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey={viewdns_api_key}&output=json"
            response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
            if response.status_code != 200:
                infos.append(f"HTTP response code {response.status_code} received from ViewDNS API !")
            else:
                results = response.json()
                if "response" in results and "domains" in results["response"]:
                    for result in results["response"]["domains"]:
                        vhost = result["name"]
                        if vhost not in infos:
                            infos.append(vhost)
        else:
            service_url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
            response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
            if response.status_code != 200:
                infos.append(f"HTTP response code {response.status_code} received from ViewDNS site !")
            else:
                results = response.text
                vhosts = re.findall(r'<td>([a-zA-Z0-9\-\.]+)<\/td>', results)
                for vhost in vhosts:
                    if "." in vhost and vhost not in infos:
                        infos.append(vhost.strip(' \r\t\n'))
        infos.sort()
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_passive_shared_hosts(ip, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # See https://www.threatminer.org/api.php
        service_url = f"https://api.threatminer.org/v2/host.php?q={ip}&rt=2"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos.append(f"HTTP response code {response.status_code} received from ThreatMiner API !")
        else:
            results = response.json()
            if results["status_code"] == "200":
                for result in results["results"]:
                    vhost = result["domain"].split(":")[0]
                    if vhost not in infos:
                        infos.append(vhost)
        infos.sort()
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_ip_owner(ip, http_proxy):
    try:
        infos = []
        data = do_whois(ip)
        records = data.splitlines()
        records_skip_prefix = ["Ref:", "OrgTech", "OrgAbuse", "OrgNOC", "tech-c", "admin-c", "remarks", "e-mail", "abuse", "Comment", "#", "%"]
        for record in records:
            if len(record.strip()) == 0:
                continue
            skip_it = False
            for prefix in records_skip_prefix:
                if record.startswith(prefix):
                    skip_it = True
                    break
            if not skip_it:
                infos.append(record)
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_shodan_ip_infos(ip, api_key, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # See https://developer.shodan.io/api
        service_url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}&minify=true"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos.append(f"HTTP response code {response.status_code} received!")
            return infos
        data = response.json()
        value = data["last_update"]
        infos.append(f"Last scan date = {value}")
        value = data["isp"]
        infos.append(f"ISP = {value}")
        value = data["org"]
        infos.append(f"Organization = {value}")
        value = " , ".join(data["hostnames"])
        infos.append(f"Hostnames = {value}")
        value = data["ports"]
        infos.append(f"Ports = {value}")
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_shodan_cpe_cve_infos(ip, api_key, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # See https://developer.shodan.io/api
        # Note: Historical IP lookups require a membership or API subscription
        service_url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}&history=false"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos.append(
                f"HTTP response code {response.status_code} received!")
            return infos
        data = response.json()
        if "data" in data:
            # Extract the whole list of CPE and CVE detected by Shodan gathered by scan date
            cpe_cve_collection = collections.OrderedDict()
            for record in data["data"]:
                if "cpe" in record or "vulns" in record:
                    timestamp = record["timestamp"]
                    if timestamp not in cpe_cve_collection:
                        cpe_cve_collection[timestamp] = {"CPE": [], "CVE": []}
                    if "cpe" in record:
                        cpe_cve_collection[timestamp]["CPE"].extend(
                            record["cpe"])
                    if "vulns" in record and len(record["vulns"]) > 0:
                        cves = []
                        vulns = record["vulns"]
                        for vuln_id in vulns:
                            summary = vulns[vuln_id]["summary"]
                            if len(summary) > 100:
                                summary = summary[:100] + "..."
                            cves.append(
                                "CVSS " + str(vulns[vuln_id]["cvss"]) + " - " + vuln_id + " - " + summary)
                        cves.sort(reverse=True)  # Highest CVSS score on top
                        cpe_cve_collection[timestamp]["CVE"].extend(cves)
            # Extract interesting infos by showing detected CPE with their associated CVE
            cpe_already_extracted = []
            cve_already_extracted = []
            for cpe_cve_record in cpe_cve_collection:
                scan_date_already_added = False
                for cpe in cpe_cve_collection[cpe_cve_record]["CPE"]:
                    if cpe not in cpe_already_extracted:
                        if not scan_date_already_added:
                            infos.append(f"Scan date {cpe_cve_record}:")
                            scan_date_already_added = True
                        value = f"  Detected software: '{cpe}'"
                        infos.append(value)
                        cpe_already_extracted.append(cpe)
                for cve in cpe_cve_collection[cpe_cve_record]["CVE"]:
                    if cve not in cve_already_extracted:
                        infos.append(f"  Detected CVE: {cve}")
                        cve_already_extracted.append(cve)
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_qualys_sslscan_cached_infos(domain, ip, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # See https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
        service_url = f"https://api.ssllabs.com/api/v3/getEndpointData?host={domain}&s={ip}&fromCache=on"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if "errors" not in response.text and "statusMessage" not in response.text:
            infos.append(f"HTTP response code {response.status_code} received!")
            return infos
        data = response.json()
        if "errors" in data:
            error_msg = ""
            for error in data["errors"]:
                error_msg += error["message"]
            infos.append(f"{error_msg}")
        if "statusMessage" in data and data["statusMessage"] == "Ready":
            if "ipAddress" in data:
                value = data["ipAddress"]
                infos.append(f"IPAddress = {value}")
            if "serverName" in data:
                value = data["serverName"]
                infos.append(f"ServerName = {value}")
            if "grade" in data:
                value = data["grade"]
                infos.append(f"Grade = {value}")
            if "details" in data:
                details = data["details"]
                value = datetime.datetime.fromtimestamp(
                    details["hostStartTime"]/1000.0).strftime("%Y-%d-%mT%H:%M:%S")
                infos.append(f"AssessmentStartingTime = {value}")
                value = details["vulnBeast"]
                infos.append(f"BEAST = {value}")
                value = details["heartbleed"]
                infos.append(f"HEARTBLEED = {value}")
                value = details["poodle"]
                infos.append(f"POODLE = {value}")
                value = details["freak"]
                infos.append(f"FREAK = {value}")
                value = details["logjam"]
                infos.append(f"LOGJAM = {value}")
                if "drownVulnerable" in details:
                    value = details["drownVulnerable"]
                    infos.append(f"DROWN = {value}")
                value = (details["ticketbleed"] == 2)
                infos.append(f"TICKETBLEED = {value}")
                value = (details["bleichenbacher"] ==
                         2 or details["bleichenbacher"] == 3)
                infos.append(f"ROBOT = {value}")
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_hybrid_analysis_report_infos(query, api_key, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # See https://www.hybrid-analysis.com/docs/api/v2
        service_url = f"https://www.hybrid-analysis.com/api/search?query={query}"
        response = requests.get(service_url, headers={"User-Agent": "Falcon", "api-key": api_key}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos.append(f"HTTP response code {response.status_code} received!")
            return infos
        data = response.json()
        rc = data["response_code"]
        if rc == 0:
            if len(data["response"]["result"]) > 0:
                result = data["response"]["result"][0]
                infos.append(f"Verdict = {result['verdict'].capitalize()}")
                infos.append(f"Analysis time = {result['start_time']}")
            else:
                infos.append("No report found")
        else:
            infos.append(f"Call to API failed (RC = {rc})")
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_virus_total_report_infos(domain, ip_list, api_key, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = {}
        # See https://developers.virustotal.com/reference
        # Note: As VT as a limit of 4 requests by minute then this function
        # handle globally the retrieval of infos from VT and handle this limitation
        # Get info for the domain
        vt_call_count = 0
        service_url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        vt_call_count += 1
        infos[domain] = extract_infos_from_virus_total_response(response)
        # Get info for the IPs
        for ip in ip_list:
            if vt_call_count > 4:
                time.sleep(60)
                vt_call_count = 0
            service_url = f"https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={api_key}&ip={ip}"
            response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
            vt_call_count += 1
            infos[ip] = extract_infos_from_virus_total_response(response)
        return infos
    except RequestException as e:
        msg = [f"Error during web call: {str(e)}"]
        infos = {}
        infos[domain] = msg
        for ip in ip_list:
            infos[ip] = msg
        return infos


def get_certificate_transparency_log_subdomains(domain, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # See https://crt.sh
        service_url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos.append(f"HTTP response code {response.status_code} received!")
            return infos
        results = response.json()
        for entry in results:
            cert_name = f"{entry['name_value']} ({entry['issuer_name']})"
            if cert_name not in infos:
                infos.append(cert_name)
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_github_repositories(domain_or_ip, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = []
        # See https://developer.github.com/v3/search/#search-repositories
        term = f"%22{domain_or_ip}%22"
        service_url = f"https://api.github.com/search/repositories?q=size:%3E0+{term}&sort=updated&order=desc"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos.append(f"HTTP response code {response.status_code} received!")
            return infos
        results = response.json()
        for repo in results["items"]:
            html_url = repo["html_url"]
            is_fork = repo["fork"]
            forks = repo["forks"]
            watchers = repo["watchers"]
            infos.append(
                f"{html_url} (IsFork: {is_fork} - Forks: {forks} - Watchers: {watchers})")
        return infos
    except RequestException as e:
        return [f"Error during web call: {str(e)}"]


def get_softwareheritage_infos(domain_or_ip, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = {"DATA": [], "LIMIT": "NA"}
        # See https://archive.softwareheritage.org/api
        service_url = f"https://archive.softwareheritage.org/api/1/origin/search/{domain_or_ip}/?limit=1000&with_visit=true"
        # Set a long timeout (up to 4 minutes) because the response take a while to reply
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos["DATA"].append(f"HTTP response code {response.status_code} received!")
            return infos
        results = response.json()
        remaining_allowed_call_for_current_hour = response.headers["X-RateLimit-Remaining"]
        next_call_count_reset = datetime.datetime.fromtimestamp(int(response.headers["X-RateLimit-Reset"]))
        infos["LIMIT"] = f"{remaining_allowed_call_for_current_hour} call(s) can still be performed in the current hours (reseted at {next_call_count_reset})."
        for entry in results:
            infos["DATA"].append(entry["url"])
        return infos
    except RequestException as e:
        infos = {"DATA": [f"Error during web call: {str(e)}"], "LIMIT": "NA"}
        return infos


def get_wpr_version():
    version = "NA"
    try:
        repo = git.Repo(search_parent_directories=False)
        sha = repo.head.object.hexsha
        if sha is not None and len(sha.strip(" ")) > 0:
            version = sha[0:7]
    except:
        pass
    return version


def is_valid(domain):
    parsed = urllib.parse.urlparse(domain)
    return (len(parsed.scheme) == 0 and len(parsed.params) == 0 and len(parsed.query) == 0 and len(parsed.fragment) == 0)


def get_mobile_app_infos(domain, http_proxy):
    try:
        web_proxies = configure_proxy(http_proxy)
        infos = {"DATA": [], "ERROR": None}
        domain_infos = tldextract.extract(domain)
        base_domain = f"{domain_infos.domain}.{domain_infos.suffix}"
        base_domain_name = f"{domain_infos.domain}"
        # iOS platform
        # See https://performance-partners.apple.com/search-api
        # See https://stackoverflow.com/a/16903522
        found = False
        service_url = f"https://itunes.apple.com/search?term={base_domain_name}&entity=software&country={MOBILE_APP_STORE_COUNTRY_STORE_CODE}"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos["DATA"].append(f"HTTP response code {response.status_code} received!")
            return infos
        results = response.json()
        for entry in results["results"]:
            if "sellerUrl" in entry and base_domain.lower() in entry["sellerUrl"].lower():
                infos["DATA"].append(f"iOS app found with TrackName '{entry['trackName']}' and BundleId '{entry['bundleId']}'.")
                found = True
        if not found:
            infos["DATA"].append("No iOS app found.")
        # Android platform
        service_url = f"https://play.google.com/store/search?q={base_domain_name}&c=apps&hl=en&gl={MOBILE_APP_STORE_COUNTRY_STORE_CODE}"
        response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
        if response.status_code != 200:
            infos["DATA"].append(f"HTTP response code {response.status_code} received!")
            return infos
        results = response.text
        android_bundle_regex = f"id=({domain_infos.suffix}\\.{domain_infos.domain}\\.[a-z0-9A-Z\\.\\-_]+)"
        bundles = re.findall(android_bundle_regex, results)
        for bundle in bundles:
            infos["DATA"].append(f"Android app found with PackageId '{bundle}'.")
        if len(bundles) == 0:
            infos["DATA"].append("No Android app found.")
    except Exception as e:
        infos["ERROR"] = f"Error during web call: {str(e)}"
        infos["DATA"].clear()
    return infos


def get_dns_dumpster_infos(domain, http_proxy):
    infos = {"DATA": [], "XLS": None, "IMG": None, "ERROR": None}
    try:
        web_proxies = configure_proxy(http_proxy)
        req_session = requests.Session()
        req_session.headers.update({"User-Agent": USER_AGENT})
        req_session.proxies.update(web_proxies)
        req_session.verify = (http_proxy is None)
        results = DNSDumpsterAPI(session=req_session).search(domain)
        if len(results) > 0:
            data = results["dns_records"]
            for entry in data["dns"]:
                infos["DATA"].append(f"[DNS ]: IP \"{entry['ip']}\" - Domain \"{entry['domain']}\" - ReverseDNS \"{entry['reverse_dns']}\" - AS \"{entry['as']}\"")
            for entry in data["mx"]:
                infos["DATA"].append(f"[MX  ]: IP \"{entry['ip']}\" - Domain \"{entry['domain']}\" - ReverseDNS \"{entry['reverse_dns']}\" - AS \"{entry['as']}\"")
            for entry in data["txt"]:
                infos["DATA"].append(f"[TXT ]: {entry}")
            for entry in data["host"]:
                infos["DATA"].append(f"[HOST]: IP \"{entry['ip']}\" - Domain \"{entry['domain']}\" - ReverseDNS \"{entry['reverse_dns']}\" - AS \"{entry['as']}\"")
            if results["xls_data"] != None:
                infos["XLS"] = base64.b64decode(results["xls_data"])
            if results["image_data"] != None:
                infos["IMG"] = base64.b64decode(results["image_data"])
            infos["DATA"].sort()
    except Exception as e:
        infos["ERROR"] = f"Error during web call: {str(e)}"
        infos["DATA"].clear()
        infos["XLS"] = None
        infos["IMG"] = None
    return infos


def get_grayhatwarfare_infos(domain, api_key, http_proxy):
    infos = {"DATA": [], "ERROR": None}
    service_url_files = f"https://buckets.grayhatwarfare.com/api/v2/files?keywords={domain}&limit=1000"
    service_url_buckets = f"https://buckets.grayhatwarfare.com/api/v2/buckets?keywords={domain}&limit=1000"
    try:
        web_proxies = configure_proxy(http_proxy)
        req_session = requests.Session()
        req_session.headers.update({"User-Agent": USER_AGENT, "Authorization": f"Bearer {api_key}"})
        req_session.proxies.update(web_proxies)
        req_session.verify = (http_proxy is None)
        # Extract data for files
        response = req_session.get(service_url_files)
        if response.status_code != 200:
            infos["ERROR"] = f"HTTP response code {response.status_code} received (files)!"
            infos["DATA"].clear()
            return infos
        results = response.json()
        if len(results["files"]) > 0:
            for file in results["files"]:
                infos["DATA"].append(f"[FILE  ]: {file['url']} ({file['size']} bytes)")
        # Extract data for buckets
        response = req_session.get(service_url_buckets)
        if response.status_code != 200:
            infos["ERROR"] = f"HTTP response code {response.status_code} received (buckets)!"
            infos["DATA"].clear()
            return infos
        results = response.json()
        if len(results["buckets"]) > 0:
            for bucket in results["buckets"]:
                if "container" in bucket:
                    infos["DATA"].append(f"[BUCKET]: '{bucket['bucket']}' in container '{bucket['container']}' ({bucket['fileCount']} files)")
                else:
                    infos["DATA"].append(f"[BUCKET]: '{bucket['bucket']}' ({bucket['fileCount']} files)")
        infos["DATA"].sort()
    except Exception as e:
        infos["ERROR"] = f"Error during web call: {str(e)}"
        infos["DATA"].clear()
    return infos


def get_wayback_machine_infos(domain, http_proxy):
    infos = {"DATA": [], "ERROR": None}
    # See https://archive.org/help/wayback_api.php
    service_url = f"https://archive.org/wayback/available?url={domain}"
    try:
        web_proxies = configure_proxy(http_proxy)
        req_session = requests.Session()
        req_session.headers.update({"User-Agent": USER_AGENT})
        req_session.proxies.update(web_proxies)
        req_session.verify = (http_proxy is None)
        # Extract data for files
        response = req_session.get(service_url)
        if response.status_code != 200:
            infos["ERROR"] = f"HTTP response code {response.status_code} received!"
            infos["DATA"].clear()
            return infos
        results = response.json()
        if "closest" in results["archived_snapshots"]:
            url = results["archived_snapshots"]["closest"]["url"]
            last_scan_date = "N/A"
            if "timestamp" in results["archived_snapshots"]["closest"]:
                # Ex: 20220603141821
                last_scan_date = datetime.datetime.strptime(results["archived_snapshots"]["closest"]["timestamp"], "%Y%m%d%H%M%S").strftime("%d/%m/%Y at %H:%M:%S")
            infos["DATA"].append(f"URL to access to the history: {url}")
            infos["DATA"].append(f"Most recent archived snapshot taken on {last_scan_date}.")
    except Exception as e:
        infos["ERROR"] = f"Error during web call: {str(e)}"
        infos["DATA"].clear()
    return infos


def get_pgp_users_infos(domain, http_proxy):
    infos = {"DATA": [], "ERROR": None}
    # See https://openpgp.circl.lu
    service_url = f"https://openpgp.circl.lu/pks/lookup?search={domain}&options=mr&op=index"
    try:
        web_proxies = configure_proxy(http_proxy)
        req_session = requests.Session()
        req_session.headers.update({"User-Agent": USER_AGENT})
        req_session.proxies.update(web_proxies)
        req_session.verify = (http_proxy is None)
        response = req_session.get(service_url)
        if response.status_code != 200:
            infos["ERROR"] = f"HTTP response code {response.status_code} received!"
            infos["DATA"].clear()
            return infos
        results = response.text
        for entry in results.splitlines():
            if entry.startswith("uid:"):
                v = entry.split(":")[1]
                if v not in infos["DATA"]:
                    infos["DATA"].append(v)
        infos["DATA"].sort()
    except Exception as e:
        infos["ERROR"] = f"Error during web call: {str(e)}"
        infos["DATA"].clear()
    return infos


def get_leakix_info(field_type, field_value, http_proxy):
    infos = {"DATA": [], "ERROR": None}
    # See https://files.leakix.net/p/api
    service_url = f"https://files.leakix.net/json?q={field_type}:{field_value}"
    try:
        web_proxies = configure_proxy(http_proxy)
        req_session = requests.Session()
        req_session.headers.update({"User-Agent": USER_AGENT})
        req_session.proxies.update(web_proxies)
        req_session.verify = (http_proxy is None)
        response = req_session.get(service_url)
        if response.status_code != 200:
            infos["ERROR"] = f"HTTP response code {response.status_code} received!"
            infos["DATA"].clear()
            return infos
        results = response.json()
        status = results["status"]
        if status == "success":
            for entry in results["data"]:
                last_changed = entry["last-modified"].split("T")[0]
                file_url = entry["url"]
                v = f"{last_changed}: {file_url}"
                if v not in infos["DATA"]:
                    infos["DATA"].append(v)
            infos["DATA"].sort()
        else:
            infos["ERROR"] = f"Status '{status}' received!"
            infos["DATA"].clear()
    except Exception as e:
        infos["ERROR"] = f"Error during web call: {str(e)}"
        infos["DATA"].clear()
    return infos


def get_napalm_ftp_indexer_info(domain, http_proxy):
    infos = {"DATA": [], "ERROR": None}
    # See https://www.searchftps.net/
    service_url = f"https://www.searchftps.net/"
    expected_response_marker = "showing results"
    regex_results_count = r'Showing\s+results\s+\d+\s+to\s+\d+\s+of\s+about\s+(\d+)'
    try:
        web_proxies = configure_proxy(http_proxy)
        req_session = requests.Session()
        req_session.headers.update({"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"})
        req_session.proxies.update(web_proxies)
        req_session.verify = (http_proxy is None)
        form_data = {"action": "result", "args": f"k={domain}&t=and&o=date-desc&s=0"}
        response = req_session.post(url=service_url, data=form_data)
        if response.status_code != 200:
            infos["ERROR"] = f"HTTP response code {response.status_code} received!"
            infos["DATA"].clear()
            return infos
        results = response.text
        if expected_response_marker not in results.lower():
            with open("debug.tmp", mode="w", encoding="utf-8") as f:
                f.write(results)
            infos["ERROR"] = f"Non expected response received, marker '{expected_response_marker}' not found, see 'debug.tmp' file generated."
            infos["DATA"].clear()
            return infos
        results_count = re.findall(regex_results_count, results, re.IGNORECASE | re.MULTILINE)
        if len(results_count) > 0 and int(results_count[0]) > 0:
            infos["DATA"].append(f"{results_count[0]} entries present on the site.")
    except Exception as e:
        infos["ERROR"] = f"Error during web call: {str(e)}"
        infos["DATA"].clear()
    return infos


def get_proxynova_comb_info(domain, http_proxy):
    infos = {"DATA": [], "ERROR": None}
    # See proxynova
    service_url = f"https://api.proxynova.com/comb?query={domain}&start=0&limit=100"
    try:
        web_proxies = configure_proxy(http_proxy)
        req_session = requests.Session()
        req_session.headers.update({"User-Agent": USER_AGENT})
        req_session.proxies.update(web_proxies)
        req_session.verify = (http_proxy is None)
        response = req_session.get(url=service_url)
        if response.status_code != 200:
            infos["ERROR"] = f"HTTP response code {response.status_code} received!"
            infos["DATA"].clear()
            return infos
        results = response.json()
        if results["count"] > 0:
            for line in results["lines"]:
                infos["DATA"].append(line)
    except Exception as e:
        infos["ERROR"] = f"Error during web call: {str(e)}"
        infos["DATA"].clear()
    return infos


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    colorama.init()
    start_time = time.time()
    parser = argparse.ArgumentParser()
    required_params = parser.add_argument_group("required arguments")
    required_params.add_argument("-d", action="store", dest="domain_name", help="Domain to analyse (ex: righettod.eu).", required=True)
    parser.add_argument("-a", action="store", dest="api_key_file", default=None, help="Configuration INI file with all API keys (ex: conf.ini).", required=False)
    parser.add_argument("-n", action="store", dest="name_server", default=None, help="Name server to use for the DNS query (ex: 8.8.8.8).", required=False)
    parser.add_argument("-p", action="store", dest="http_proxy", default=None, help="HTTP proxy to use for all HTTP call to differents services (ex: http://88.198.50.103:9080).", required=False)
    parser.add_argument("-s", action="store_true", dest="store_filetype_dork_result", default=False, help="Save the result of the Google/Bing Dork searching for interesting files to the file 'filetype_dork_result.txt'.", required=False)
    parser.add_argument("-t", action="store", dest="request_timeout", type=int, default=DEFAULT_CALL_TIMEOUT, help="Delay in seconds allowed for a HTTP request to reply before to fall in timeout (ex: 20).", required=False)
    parser.add_argument("-m", action="store", dest="mobile_app_store_country_code", default=MOBILE_APP_STORE_COUNTRY_STORE_CODE, help="Country code to define in which store mobile app will be searched (ex: LU).", required=False)
    args = parser.parse_args()
    api_key_config = configparser.ConfigParser()
    api_key_config["API_KEYS"] = {}
    http_proxy_to_use = args.http_proxy
    wpr_version = get_wpr_version()
    print(colored("####################################################", "blue", attrs=["bold"]))
    print(colored("### WEB PASSIVE RECONNAISSANCE", "blue", attrs=["bold"]))
    print(colored(f"### COMMIT VERSION : {wpr_version}", "blue", attrs=["bold"]))
    print(colored(f"### TARGET DOMAIN  : {args.domain_name.upper()}", "blue", attrs=["bold"]))
    print(colored(f"####################################################", "blue", attrs=["bold"]))
    if not is_valid(args.domain_name):
        print(colored(f"A domain must be provided and not a URL!", "red", attrs=["bold"]))
        print(colored(f".::Reconnaissance aborted::.", "red", attrs=["bold"]))
        sys.exit(1)
    if args.api_key_file is not None:
        api_key_config.read(args.api_key_file)
        api_keys_names = " / ".join(api_key_config["API_KEYS"].keys())
        print(colored(f"[CONF] API key file '{args.api_key_file}' loaded: {api_keys_names}.", "white", attrs=["bold"]))
    if args.name_server is not None:
        print(colored(f"[CONF] Name server '{args.name_server}' used for all DNS queries.", "white", attrs=["bold"]))
    else:
        print(colored(f"[CONF] System default name server used for all DNS queries.", "white", attrs=["bold"]))
    if args.request_timeout is not None and args.request_timeout > 1:
        DEFAULT_CALL_TIMEOUT = args.request_timeout
    print(colored(f"[CONF] Request reply timeout set to {DEFAULT_CALL_TIMEOUT} seconds.", "white", attrs=["bold"]))
    if http_proxy_to_use is not None:
        print(colored(f"[CONF] HTTP proxy '{http_proxy_to_use}' used for all HTTP requests.", "white", attrs=["bold"]))
        if args.api_key_file is not None:
            print(colored(f"[WARNING] Be aware that your API keys will be visible by the specified proxy!", "yellow", attrs=["bold"]))
        print("Test proxy connectivity...", end='')
        msg = test_proxy_connectivity(http_proxy_to_use)
        if msg.startswith("Succeed"):
            print(colored(msg, "green", attrs=[]))
        else:
            print(colored(msg, "red", attrs=[]))
            print(colored(f".::Reconnaissance aborted::.", "red", attrs=["bold"]))
            sys.exit(1)
    else:
        print(colored(f"[CONF] No HTTP proxy used for all HTTP requests.", "white", attrs=["bold"]))
    if args.mobile_app_store_country_code != MOBILE_APP_STORE_COUNTRY_STORE_CODE:
        MOBILE_APP_STORE_COUNTRY_STORE_CODE = args.mobile_app_store_country_code.upper()
        print(colored(f"[CONF] App store for country code '{MOBILE_APP_STORE_COUNTRY_STORE_CODE}' used for mobile apps searches.", "white", attrs=["bold"]))
    print(colored(f"[DNS] Extract the IP V4/V6 addresses...", "blue", attrs=["bold"]))
    ips = get_ip_addresses(args.domain_name, args.name_server, ["A", "AAAA"])
    if not ips:
        print(colored(f".::Unable to resolve DNS - Reconnaissance aborted::.", "red", attrs=["bold"]))
        sys.exit(2)
    print_infos(ips)
    print(colored(f"[DNS] Extract the aliases...", "blue", attrs=["bold"]))
    cnames = get_cnames(args.domain_name, args.name_server)
    print_infos(cnames)
    print(colored(f"[WHOIS] Extract the owner information of the IP addresses...", "blue", attrs=["bold"]))
    for ip in ips:
        print(colored(f"{ip}", "yellow", attrs=["bold"]))
        informations = get_ip_owner(ip, http_proxy_to_use)
        print_infos(informations, "  ")
    print(colored(f"[SHODAN] Extract the general information of the IP addresses and the domain...", "blue", attrs=["bold"]))
    if "shodan" in api_key_config["API_KEYS"]:
        api_key = api_key_config["API_KEYS"]["shodan"]
        print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
        print("  Search with filter using the API with a free tier API key is not allowed, so, use the following URL from a browser:")
        print(f"    https://www.shodan.io/search?query=hostname%3A{args.domain_name}")
        is_single_ip = len(ips) < 2
        for ip in ips:
            print(colored(f"{ip}", "yellow", attrs=["bold"]))
            informations = get_shodan_ip_infos(ip, api_key, http_proxy_to_use)
            print_infos(informations, "  ")
            # Add tempo due to API limitation (API methods are rate-limited to 1 request by second)
            if not is_single_ip:
                time.sleep(1)
    else:
        print(colored(f"Skipped because no API key was specified!", "red", attrs=["bold"]))
    print(colored(f"[SHODAN] Extract the CPE/CVE information of the IP addresses...", "blue", attrs=["bold"]))
    if "shodan" in api_key_config["API_KEYS"]:
        api_key = api_key_config["API_KEYS"]["shodan"]
        is_single_ip = len(ips) < 2
        for ip in ips:
            print(colored(f"{ip}", "yellow", attrs=["bold"]))
            informations = get_shodan_cpe_cve_infos(ip, api_key, http_proxy_to_use)
            print_infos(informations, "  ")
            # Add tempo due to API limitation (API methods are rate-limited to 1 request by second)
            if not is_single_ip:
                time.sleep(1)
    else:
        print(colored(f"Skipped because no API key was specified!", "red", attrs=["bold"]))
    print(colored(f"[HACKERTARGET+VIEWDNS] Extract current hosts shared by each IP address (active DNS)...", "blue", attrs=["bold"]))
    viewdns_api_key = None
    if "viewdns" in api_key_config["API_KEYS"]:
        viewdns_api_key = api_key_config["API_KEYS"]["viewdns"]
    if viewdns_api_key is None:
        print(colored("[i]", "green") + " ViewDNS API key not specified so only free data was retrieved (first 1000 records).")
    for ip in ips:
        print(colored(f"{ip}", "yellow", attrs=["bold"]))
        if ":" in ip:
            print_infos(["IPV6 not supported"], "  ")
            continue
        informations = get_active_shared_hosts(ip, http_proxy_to_use, viewdns_api_key)
        print_infos(informations, "  ")
    print(colored(f"[THREATMINER] Extract previous hosts shared by each IP address (passive DNS)...", "blue", attrs=["bold"]))
    for ip in ips:
        print(colored(f"{ip}", "yellow", attrs=["bold"]))
        informations = get_passive_shared_hosts(ip, http_proxy_to_use)
        print_infos(informations, "  ")
    print(colored(f"[NETCRAFT] Provide the URL to report for the IP addresses and the domain...", "blue", attrs=["bold"]))
    print("No API provided and browser required, so, use the following URL from a browser:")
    print(f"  https://toolbar.netcraft.com/site_report?url={args.domain_name}")
    for ip in ips:
        print(f"  https://toolbar.netcraft.com/site_report?url={ip}")
    print(colored(f"[PASTEBIN via GOOGLE] Apply Google Dork for the domain...", "blue", attrs=["bold"]))
    dork = f"site:pastebin.com \"{args.domain_name}\""
    print("Perform the following dork: " + colored(f"{dork}", "yellow", attrs=["bold"]))
    informations = get_google_dork_results(dork, http_proxy_to_use)
    print_infos(informations, "  ")
    print(colored(f"[GOOGLE] Apply several Google Dorks for the domain...", "blue", attrs=["bold"]))
    file_types = " OR filetype:".join(INTERESTING_FILE_EXTENSIONS)
    dork = f"site:{args.domain_name} filetype:{file_types}"
    print("Perform the following dork: " + colored(f"{dork}", "yellow", attrs=["bold"]))
    informations = get_google_dork_results(dork, http_proxy_to_use)
    print_infos(informations, "  ")
    if args.store_filetype_dork_result and informations != None and len(informations) > 0 and "HTTP Error" not in informations[0]:
        file_name = "filetype_dork_result1.txt"
        with open(file_name, "a+") as f:
            f.write("\n")
            f.write("\n".join(informations[1:]))
        print(colored("[i]", "green") + " " + str(len(informations) - 1) + f" results saved to '{file_name}' file.")
    dork = RCE_PRONE_PARAMETERS_DORK % args.domain_name
    print("Perform the following dork: " + colored(f"{dork}", "yellow", attrs=["bold"]))
    informations = get_google_dork_results(dork, http_proxy_to_use)
    print_infos(informations, "  ")
    if args.store_filetype_dork_result and informations != None and len(informations) > 0 and "HTTP Error" not in informations[0]:
        file_name = "filetype_dork_result2.txt"
        with open(file_name, "a+") as f:
            f.write("\n")
            f.write("\n".join(informations[1:]))
        print(colored("[i]", "green") + " " + str(len(informations) - 1) + f" results saved to '{file_name}' file.")
    print(colored(f"[PASTEBIN via BING] Apply Bing Dork for the domain, get the 50 first records (max per page allowed by the API)...", "blue", attrs=["bold"]))
    if "azure-cognitive-services-bing-web-search" in api_key_config["API_KEYS"]:
        api_key = api_key_config["API_KEYS"]["azure-cognitive-services-bing-web-search"]
        dork = f"site:pastebin.com \"{args.domain_name}\""
        print("Perform the following dork: " + colored(f"{dork}", "yellow", attrs=["bold"]))
        informations = get_bing_dork_results(dork, api_key, http_proxy_to_use)
        print_infos(informations, "  ")
    else:
        print(colored(f"Skipped because no API key was specified!", "red", attrs=["bold"]))
    print(colored(f"[BING] Apply Bing Dork for the domain, get the 50 first records (max per page allowed by the API)...", "blue", attrs=["bold"]))
    if "azure-cognitive-services-bing-web-search" in api_key_config["API_KEYS"]:
        file_types = " OR filetype:".join(INTERESTING_FILE_EXTENSIONS)
        dork = f"site:{args.domain_name} AND (filetype:{file_types})"
        print("Perform the following dork: " + colored(f"{dork}", "yellow", attrs=["bold"]))
        informations = get_bing_dork_results(dork, api_key, http_proxy_to_use)
        print_infos(informations, "  ")
        if args.store_filetype_dork_result and informations != None and len(informations) > 0 and "HTTP Error" not in informations[0]:
            file_name = "filetype_dork_result.txt"
            with open(file_name, "a+") as f:
                f.write("\n")
                f.write("\n".join(informations[1:]))
            print(colored("[i]", "green") + " " + str(len(informations) - 1) + f" results saved to '{file_name}' file.")
    else:
        print(colored(f"Skipped because no API key was specified!", "red", attrs=["bold"]))
    print(colored(f"[WAYBACKMACHINE] Provide the URL for Internet Archive (Wayback Machine) for the domain...", "blue", attrs=["bold"]))
    print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
    informations = get_wayback_machine_infos(args.domain_name, http_proxy_to_use)
    if informations["ERROR"] is not None:
        print(f"  {informations['ERROR']}")
    else:
        print_infos(informations["DATA"], "  ")
    print(colored(f"[QUALYS] Extract information from SSL cached scan for the domain and IP addresses...", "blue", attrs=["bold"]))
    for ip in ips:
        print(colored(f"{ip}", "yellow", attrs=["bold"]))
        informations = get_qualys_sslscan_cached_infos(args.domain_name, ip, http_proxy_to_use)
        print_infos(informations, "  ")
    print(colored(f"[HYBRID-ANALYSIS] Extract the verdict for the IP addresses and the domain regarding previous hosting of malicious content...", "blue", attrs=["bold"]))
    if "hybrid-analysis" in api_key_config["API_KEYS"]:
        api_key = api_key_config["API_KEYS"]["hybrid-analysis"]
        print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
        informations = get_hybrid_analysis_report_infos(f"domain:{args.domain_name}", api_key, http_proxy_to_use)
        print_infos(informations, "  ")
        for ip in ips:
            print(colored(f"{ip}", "yellow", attrs=["bold"]))
            informations = get_hybrid_analysis_report_infos(f"host:%22{ip}%22", api_key, http_proxy_to_use)
            print_infos(informations, "  ")
    else:
        print(colored(f"Skipped because no API key was specified!", "red", attrs=["bold"]))
    print(colored(f"[VIRUSTOTAL] Extract the presence for the IP addresses or the domain regarding previous hosting of malicious content...", "blue", attrs=["bold"]))
    if "virustotal" in api_key_config["API_KEYS"]:
        api_key = api_key_config["API_KEYS"]["virustotal"]
        global_informations = get_virus_total_report_infos(args.domain_name, ips, api_key, http_proxy_to_use)
        for k in global_informations:
            print(colored(f"{k}", "yellow", attrs=["bold"]))
            informations = global_informations[k]
            print_infos(informations, "  ")
    else:
        print(colored(f"Skipped because no API key was specified!", "red", attrs=["bold"]))
    print(colored(f"[CERTIFICATE-TRANSPARENCY] Extract the referenced subdomains of the target domain...", "blue", attrs=["bold"]))
    print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
    informations = get_certificate_transparency_log_subdomains(args.domain_name, http_proxy_to_use)
    print_infos(informations, "  ")
    print(colored(f"[INTELX] Check if the site contain information about the IP addresses or the domain...", "blue", attrs=["bold"]))
    print(colored("[i]", "green") + " INTELX keep a copy of pastes identified so if a paste was removed then it can be still accessed via the INTELX site.")
    if "intelx" in api_key_config["API_KEYS"]:
        api_key = api_key_config["API_KEYS"]["intelx"]
        infos_for_ip = {}
        for ip in ips:
            infos_for_ip[ip] = get_intelx_infos(ip, api_key, http_proxy_to_use)
        infos_for_domain = get_intelx_infos(args.domain_name, api_key, http_proxy_to_use)
        for ip in ips:
            print(colored(f"{ip}", "yellow", attrs=["bold"]))
            if len(infos_for_ip[ip]) > 0:
                print(
                    "  Data found (see below), so, use the following URL from a browser:")
                print(f"    https://intelx.io/?s={ip}")
            print_infos(infos_for_ip[ip], "  ")
        print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
        if len(infos_for_domain) > 0:
            print("  Data found (see below), so, use the following URL from a browser:")
            print(f"    https://intelx.io/?s={args.domain_name}")
        print_infos(infos_for_domain, "  ")
    else:
        print(colored(f"Skipped because no API key was specified!", "red", attrs=["bold"]))
    print(colored(f"[GITHUB] Extract the repositories with references to the IP addresses or the main domain in their content...", "blue", attrs=["bold"]))
    domain_no_tld = get_main_domain_without_tld(args.domain_name)
    print(colored(f"{domain_no_tld}", "yellow", attrs=["bold"]))
    informations = get_github_repositories(domain_no_tld, http_proxy_to_use)
    print_infos(informations, "  ")
    for ip in ips:
        print(colored(f"{ip}", "yellow", attrs=["bold"]))
        informations = get_github_repositories(ip, http_proxy_to_use)
        print_infos(informations, "  ")
    print(colored(f"[SOFTWAREHERITAGE] Check if the archive contain source code repositories with references to the IP addresses or the main domain in their name (can take a while)...", "blue", attrs=["bold"]))
    domain_no_tld = get_main_domain_without_tld(args.domain_name)
    print(colored(f"{domain_no_tld}", "yellow", attrs=["bold"]))
    informations = get_softwareheritage_infos(domain_no_tld, http_proxy_to_use)
    print_infos(informations["DATA"], "  ")
    for ip in ips:
        print(colored(f"{ip}", "yellow", attrs=["bold"]))
        informations = get_softwareheritage_infos(ip, http_proxy_to_use)
        print_infos(informations["DATA"], "  ")
    if informations['LIMIT'] != "NA":
        print(colored("[i]", "green") + f" {informations['LIMIT']}")
        print(colored("[i]", "green") + f" Use the following URL pattern to browse the archived data:")
        print("    https://archive.softwareheritage.org/browse/origin/directory/?origin_url=[ENTRY_URL]")
    print(colored(f"[DNSDUMPSTER] Retrieve the cartography information about the domain and save the Excel/Image as 'dnsdumpster.(xlsx|png)' files...", "blue", attrs=["bold"]))
    print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
    informations = get_dns_dumpster_infos(args.domain_name, http_proxy_to_use)
    if informations["ERROR"] is not None:
        print(f"  {informations['ERROR']}")
    else:
        print_infos(informations["DATA"], prefix="  ")
        if informations["XLS"] is not None:
            with open("dnsdumpster.xlsx", "wb") as f:
                f.write(informations["XLS"])
        if informations["IMG"] is not None:
            with open("dnsdumpster.png", "wb") as f:
                f.write(informations["IMG"])
    print(colored(f"[GRAYHATWARFARE] Retrieve files in AWS/AZURE buckets with reference to the domain...", "blue", attrs=["bold"]))
    if "grayhatwarfare" in api_key_config["API_KEYS"]:
        api_key = api_key_config["API_KEYS"]["grayhatwarfare"]
        domain_no_tld = get_main_domain_without_tld(args.domain_name)
        print(colored(f"{domain_no_tld}", "yellow", attrs=["bold"]))
        informations = get_grayhatwarfare_infos(domain_no_tld, api_key, http_proxy_to_use)
        if informations["ERROR"] is not None:
            print(f"  {informations['ERROR']}")
        else:
            print_infos(informations["DATA"], prefix="  ")
    else:
        print(colored(f"Skipped because no API key was specified!", "red", attrs=["bold"]))
    print(colored(f"[GOOGLE PLAY + APPLE APP STORE] Verify if the company provide mobile apps on official stores...", "blue", attrs=["bold"]))
    print(colored("[i]", "green") + f" Searches were performed into application stores for the country code '{MOBILE_APP_STORE_COUNTRY_STORE_CODE}'.")
    print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
    informations = get_mobile_app_infos(args.domain_name, http_proxy_to_use)
    if informations["ERROR"] is not None:
        print(f"  {informations['ERROR']}")
    else:
        print_infos(informations["DATA"], prefix="  ")
    print(colored(f"[OPENPGP KEYSERVER CIRCL.LU] Extract user entries for email domain '{args.domain_name}' to obtain username patterns...", "blue", attrs=["bold"]))
    informations = get_pgp_users_infos(args.domain_name, http_proxy_to_use)
    if informations["ERROR"] is not None:
        print(f"  {informations['ERROR']}")
    else:
        print_infos(informations["DATA"], prefix="  ")
    print(colored(f"[FILES.LEAKIX.NET] Retrieve leaked files for domain '{args.domain_name}' and IPv4 addresses...", "blue", attrs=["bold"]))
    print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
    informations = get_leakix_info("host", args.domain_name, http_proxy_to_use)
    print_infos(informations["DATA"], "  ")
    for ip in ips:
        # Skip IPV6
        if ":" not in ip:
            print(colored(f"{ip}", "yellow", attrs=["bold"]))
            informations = get_leakix_info("ip", ip, http_proxy_to_use)
            print_infos(informations["DATA"], "  ")
    print(colored(f"[SEARCH.0T.ROCKS] Provide the URL to data for domain '{args.domain_name}' and IP addresses...", "blue", attrs=["bold"]))
    print(colored("[i]", "green") + f" Use the following URL pattern to browse the data due to Cloudflare protection.")
    print(f"  https://search.0t.rocks/records?domain={args.domain_name}")
    for ip in ips:
        print(f"  https://search.0t.rocks/records?ips={ip}")
    print(colored(f"[NAPALM FTP INDEXER] Verify if entries are present for domain '{args.domain_name}', domain without TLD '{domain_no_tld}' and IPv4 addresses...", "blue", attrs=["bold"]))
    print(colored("[i]", "green") + f" Go to https://www.searchftps.net for the details and content.")
    print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
    informations = get_napalm_ftp_indexer_info(args.domain_name, http_proxy_to_use)
    print_infos(informations["DATA"], "  ")
    print(colored(f"{domain_no_tld}", "yellow", attrs=["bold"]))
    informations = get_napalm_ftp_indexer_info(domain_no_tld, http_proxy_to_use)
    print_infos(informations["DATA"], "  ")
    for ip in ips:
        # Skip IPV6
        if ":" not in ip:
            print(colored(f"{ip}", "yellow", attrs=["bold"]))
            informations = get_napalm_ftp_indexer_info(ip, http_proxy_to_use)
            print_infos(informations["DATA"], "  ")
    print(colored(f"[PROXYNOVA COMB] Verify if entries are present for domain '{args.domain_name}' and domain without TLD '{domain_no_tld}'...", "blue", attrs=["bold"]))
    print(colored(f"{args.domain_name}", "yellow", attrs=["bold"]))
    informations = get_proxynova_comb_info(args.domain_name, http_proxy_to_use)
    print_infos(informations["DATA"], "  ")
    print(colored(f"{domain_no_tld}", "yellow", attrs=["bold"]))
    informations = get_proxynova_comb_info(domain_no_tld, http_proxy_to_use)
    print_infos(informations["DATA"], "  ")
    # Final processing
    delay = round(time.time() - start_time, 2)
    print("")
    print(".::" + colored(f"Reconnaissance finished in {delay} seconds", "green", attrs=["bold"]) + "::.")
