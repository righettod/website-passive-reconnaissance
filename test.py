import requests
import datetime
import re

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0"
DEFAULT_CALL_TIMEOUT = 60  # 1 minute


def configure_proxy(http_proxy):
    web_proxies = {}
    if http_proxy is not None:
        web_proxies["http"] = http_proxy
        web_proxies["https"] = http_proxy
    return web_proxies


ip = "213.186.33.87"
web_proxies = []
http_proxy = None
infos = []


service_url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
response = requests.get(service_url, headers={"User-Agent": USER_AGENT}, proxies=web_proxies, verify=(http_proxy is None), timeout=DEFAULT_CALL_TIMEOUT)
if response.status_code != 200:
    infos.append(f"HTTP response code {response.status_code} received from ViewDNS site !")
else:
    results = response.text
    print(results)
    vhosts = re.findall(r'<td>([a-zA-Z0-9\-\.]+)<\/td>', results)
    print(vhosts)
    for vhost in vhosts:
        if "." in vhost:
            infos.append(vhost.strip(' \r\t\n'))
print(infos)
