"""
Contains functions and classes shared by all providers.
"""

import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional

import dns.resolver
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

# ----------------------
# Classes
# ----------------------
from rich.console import Console
from rich.text import Text

from wpr.constants import DEFAULT_CALL_TIMEOUT


@dataclass
class OSINTProviderData(ABC):
    """
    Represents the structured data returned by an OSINT information provider.

    Attributes:
        information_lines: A dictionary where keys are section names (e.g., "VHOSTS", "IP_INFOS")
                           and values are lists of strings, each representing a line of information
                           within that section.
        description_of_data_type: A brief description of the type of data contained within this object.
    """

    def __init__(self, information_lines: dict[str, list[str]], description_of_data_type: str):
        self.information_lines = information_lines
        self.description_of_data_type = description_of_data_type


@dataclass
class OSINTProvider(ABC):
    """
    Abstract base class for all OSINT (Open Source Intelligence) data providers.

    This class defines the common interface and attributes that every OSINT provider
    should implement or possess. Subclasses are expected to provide concrete
    implementations for fetching and processing data from specific OSINT sources.

    Attributes:
        name: The name of the OSINT provider (e.g., "Shodan", "IntelX").
        api_key: An optional API key required for authentication with the OSINT source.
                 Defaults to an empty string if no API key is needed or provided.
        target_ip_or_domain: The IP address or domain name that the provider will
                             query for information.
    """

    def __init__(self, name: str, target_ip_or_domain: str, api_key: str = ""):
        self.name = name
        self.api_key = api_key
        self.target_ip_or_domain = target_ip_or_domain

    def use_api_key(self) -> bool:
        """
        Indicates whether this OSINT provider requires an API key for operation.

        Returns:
            True if an API key is required, False otherwise.
        """
        return False

    @abstractmethod
    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        return OSINTProviderData({"": []}, "")


# ----------------------
# Functions
# ----------------------


def _do_whois_request(ip: str, whois_server: str) -> str:
    """
    Performs a raw WHOIS request to the specified server.

    Args:
        ip: The IP address to query.
        whois_server: The WHOIS server to connect to.

    Returns:
        The raw WHOIS response as a string.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((whois_server, 43))
    s.send(str(ip).encode())
    response = b""
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    return response.decode("utf-8", "ignore")


def get_whois_info(ip: str) -> dict[str, list[str]]:
    """
    Retrieves and parses WHOIS information for a given IP address.

    Args:
        ip: The IP address to query.

    Returns:
        A dictionary with parsed WHOIS information, categorized into 'RAW' and 'PARSED' sections.
    """
    whois_orgs = ["arin", "lacnic", "afrinic", "ripe", "apnic"]
    whois_server_tpl = "whois.%s.net"

    # First try with ARIN
    whois_response = _do_whois_request(ip, whois_server_tpl % "arin")

    # Check for referral and retry with the correct WHOIS server
    for line in whois_response.splitlines():
        if line.strip().startswith("Ref:"):
            link = line[4:].strip()
            org = link.split("/")[-1]
            if org.lower() in whois_orgs:
                whois_response = _do_whois_request(ip, whois_server_tpl % org)
                break

    infos = {"RAW": [line for line in whois_response.splitlines() if line.strip()], "PARSED": []}

    records_skip_prefix = ["Ref:", "OrgTech", "OrgAbuse", "OrgNOC", "tech-c", "admin-c", "remarks", "e-mail", "abuse", "Comment", "#", "%"]
    for record in whois_response.splitlines():
        if len(record.strip()) == 0:
            continue
        skip_it = False
        for prefix in records_skip_prefix:
            if record.strip().startswith(prefix):
                skip_it = True
                break
        if not skip_it:
            infos["PARSED"].append(record)

    return infos


def perform_dns_lookup(domain: str, record_types: List[str], name_server: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Performs DNS lookups for specified record types for a given domain.

    Args:
        domain: The domain name to query.
        record_types: A list of DNS record types to query (e.g., ["A", "AAAA", "CNAME", "MX", "TXT"]).
        name_server: Optional. The IP address of a specific name server to use for the query.

    Returns:
        A dictionary where keys are record types and values are lists of corresponding DNS records.
        Includes an "ERRORS" key if any lookups failed.
    """
    resolver = dns.resolver.Resolver(configure=True)
    if name_server:
        resolver.nameservers = [name_server]

    results: Dict[str, List[str]] = {}
    errors: List[str] = []

    for record_type in record_types:
        try:
            answer = resolver.resolve(domain, record_type)
            records = [data.to_text() for data in answer]
            results[record_type] = records
        except NoAnswer:
            results[record_type] = []
        except NoNameservers:
            errors.append(f"No name servers configured or reachable for {domain} ({record_type} record).")
            results[record_type] = []
        except NXDOMAIN:
            errors.append(f"Domain {domain} does not exist for {record_type} record.")
            results[record_type] = []
        except Exception as e:
            errors.append(f"An unexpected error occurred during DNS lookup for {domain} ({record_type} record): {e}")
            results[record_type] = []

    if errors:
        results["ERRORS"] = errors

    return results


def print_osint_data(data: OSINTProviderData):
    """
    Prints the structured OSINT data using the rich library for formatted output.

    Section names are printed in dark yellow, and data lines in the default color.

    Args:
        data: An OSINTProviderData object containing the information to print.
    """
    console = Console()
    for section, lines in data.information_lines.items():
        if section:  # Only print section header if it's not empty
            console.print(Text(f"[ {section} ]", style="dark_yellow"))
        for line in lines:
            console.print(line)
