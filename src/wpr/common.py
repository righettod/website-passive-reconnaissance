"""
Contains functions and classes shared by all providers.
"""

import tomllib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Dict, List, Optional

import dns.resolver
import tldextract
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers
from rich.console import Console
from rich.text import Text

from wpr.constants import DEFAULT_CALL_TIMEOUT, HEADER_LENGTH


# ----------------------
# Classes
# ----------------------
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

    def __init__(self, information_lines: dict[str, list[str]], description_of_data_type: str = ""):
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

    def get_additional_infos(self) -> str:
        """
        Additional information like for example the URL to get the details.
        """
        return ""

    @abstractmethod
    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        """
        Executes the provider query and returns the collected OSINT data.

        Args:
            req_timeout: Maximum time in seconds to wait for network responses.

        Returns:
            An OSINTProviderData object containing the structured results.
        """
        return OSINTProviderData({"": []})


# ----------------------
# Functions
# ----------------------
def perform_dns_lookup(domain: str, record_types: List[str], name_server: Optional[str] = None, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> Dict[str, List[str]]:
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
    resolver.lifetime = req_timeout

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

def get_main_domain_without_tld(domain: str) -> str:
    """
    Extracts the registrable domain name without the TLD (top-level domain) suffix.

    For example, given "sub.example.com", returns "example".

    Args:
        domain: The full domain name to parse (e.g. "sub.example.com").

    Returns:
        The domain name component without subdomains or TLD (e.g. "example").
    """
    domain_infos = tldextract.extract(domain)
    return domain_infos.domain


def print_data_gathering_progress(provider: OSINTProvider, is_end: bool = False):
    """
    Prints an inline progress indicator for the data gathering phase.

    Overwrites the current terminal line during collection and prints a
    completion message when is_end is True.

    Args:
        provider: The provider currently being queried.
        is_end: When True, prints the final completion message instead of the in-progress one.
    """
    if not is_end:
        print(f"\r🧑‍💻 Get data from '{provider.name}' provider for '{provider.target_ip_or_domain}' ip or domain...{' ':<40}", end="", flush=True)
    else:
        print(f"\r✅ Data gathering finished.{' ':<60}")

def print_header(messages: list[str]):
    """
    Prints a styled section header using the rich library.

    Surrounds the given messages with bright-cyan separator lines of fixed length.

    Args:
        messages: Lines of text to display inside the header block.
    """
    console = Console()
    color = "bright_cyan"
    separator_char = "="
    separator = separator_char * HEADER_LENGTH
    console.print(f"[{color}]{separator}[/{color}]")
    for message in messages:
        console.print(f"[{color}]{separator_char} {message}[/{color}]")
    console.print(f"[{color}]{separator}[/{color}]")

def print_osint_data(data: tuple[OSINTProvider, OSINTProviderData]):
    """
    Prints the structured OSINT data using the rich library for formatted output.

    Section names are printed in dark yellow, and data lines in the default color.

    Args:
        data: An OSINTProviderData object containing the information to print.
    """
    provider = data[0]
    provider_data = data[1]
    provider_has_data = False
    for lines in provider_data.information_lines.values():
        if len(lines) > 0:
            provider_has_data = True
            break
    if provider_has_data:
        console = Console()
        print_header([provider.name])
        if len(provider.get_additional_infos()) > 0:
            console.print(Text(f"ℹ️ {provider.get_additional_infos()}", style="bright_magenta"), highlight=False)
        for section, lines in provider_data.information_lines.items():
            if len(lines) > 0:
                console.print(f"[bright_yellow]🔬 {provider_data.description_of_data_type} for '{provider.target_ip_or_domain}' ({section.title()}):[/bright_yellow]", highlight=False)
                for line in lines:
                    console.print(line, highlight=False)

def get_wpr_version() -> str:
    """
    Returns the current version of the wpr package.

    Reads the version from the installed package metadata when available,
    and falls back to parsing pyproject.toml directly for uninstalled runs.

    Returns:
        The version string (e.g. "2.0.0").
    """
    wpr_version = "na"
    try:
        wpr_version = version("wpr")
        if wpr_version is None or wpr_version.strip() == "":
            raise PackageNotFoundError()
    except PackageNotFoundError:
        pyproject_file_location = str(Path(__file__).parent.parent.parent) + "/pyproject.toml"
        with open(pyproject_file_location, "rb") as f:
            project_metadata = tomllib.load(f)
        wpr_version = project_metadata["project"]["version"]
    return wpr_version