"""
Provider to perform google dork via the "googlesearch-python" package.
"""

from googlesearch import search

from wpr.common import OSINTProvider, OSINTProviderData
from wpr.constants import DEFAULT_CALL_TIMEOUT

INTERESTING_FILE_EXTENSIONS = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pps", "odp", "ods", "odt", "rtf", "java", "cs", "vb", "py", "rb", "zip", "tar", "gz", "7z", "eml", "msg", "sql", "ini", "xml", "back", "txt", "csv"]
# See issue https://github.com/righettod/website-passive-reconnaissance/issues/89
RCE_PRONE_PARAMETERS_DORK = "inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:& site:%s"


class Google(OSINTProvider):
    def __init__(self, ip_or_domain: str):
        super().__init__(name="GoogleDorks", target_ip_or_domain=ip_or_domain)

    def call(self, req_timeout: int = DEFAULT_CALL_TIMEOUT) -> OSINTProviderData:
        dorks = []
        dorks.append(f'site:pastebin.com "{self.target_ip_or_domain}"')
        dorks.append(" OR filetype:".join(INTERESTING_FILE_EXTENSIONS))
        dorks.append(RCE_PRONE_PARAMETERS_DORK % self.target_ip_or_domain)
        information_lines = {}
        for dork in dorks:
            information_lines[dork] = list(search(term=dork, sleep_interval=5, num_results=100, timeout=req_timeout, safe=""))
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Google Dorks for the domain")
