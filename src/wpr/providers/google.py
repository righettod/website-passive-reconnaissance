"""
Provider to perform google dork via the "googlesearch-python" package.
"""

import requests
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
        file_types = " OR filetype:".join(INTERESTING_FILE_EXTENSIONS)
        dorks = {}
        dorks["PasteBin"] = f'site:pastebin.com "{self.target_ip_or_domain}"'
        dorks["FileTypes"] = f"site:{self.target_ip_or_domain} filetype:{file_types}"
        dorks["RCE"] = RCE_PRONE_PARAMETERS_DORK % self.target_ip_or_domain
        information_lines = {}
        for dork_name, dork_expr in dorks.items():
            try:
                data = list(search(dork_expr, num_results=100, lang="en", timeout=req_timeout))
                if len(data) == 0:
                    data.append("Query found nothing but try manually the following dork from a browser:")
                    data.append(dork_expr)
                information_lines[dork_name] = data
            except requests.exceptions.HTTPError as err:
                if err.response.status_code == 429:
                    information_lines[dork_name] = ["HTTP 429 received so manual call required!", f"\nDork expression => {dork_expr}", f"\nError message   => {str(err)}\n"]
        return OSINTProviderData(information_lines=information_lines, description_of_data_type="Google Dorks for the domain")
