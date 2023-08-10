[![Known Vulnerabilities](https://snyk.io/test/github/righettod/website-passive-reconnaissance/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/righettod/website-passive-reconnaissance?targetFile=requirements.txt) ![Test application running state](https://github.com/righettod/website-passive-reconnaissance/workflows/Test%20application%20running%20state/badge.svg) ![Audit python code with CodeQL](https://github.com/righettod/website-passive-reconnaissance/actions/workflows/codeql.yml/badge.svg?branch=master)

![MadeWitVSCode](https://img.shields.io/static/v1?label=Made%20with&message=VisualStudio%20Code&color=blue&?style=for-the-badge&logo=visualstudio)  ![AutomatedWith](https://img.shields.io/static/v1?label=Automated%20with&message=GitHub%20Actions&color=blue&?style=for-the-badge&logo=github) ![AuditedWith](https://img.shields.io/static/v1?label=Audited%20with&message=Snyk&color=blueviolet&?style=for-the-badge&logo=snyk) ![AuditedWith](https://img.shields.io/static/v1?label=Audited%20with&message=GitHub%20CodeQL&color=blue&?style=for-the-badge&logo=github)

# 🎯 Objectives

Script to automate, when possible, the **[passive reconnaissance](https://www.codecademy.com/article/passive-active-reconnaissance)** performed on a website prior to an assessment (no direct hit on the target).

Also used to guide a reconnaissance phase by defining all steps (manual or automated) that must be mandatory performed.

# 📦 Requirements

Python >= **3.8**.

💬 Execution tested on the following 64 bits versions of Python via this [workflow](https://github.com/righettod/website-passive-reconnaissance/actions/workflows/pythonapp.yml):

| Version | Supported? |
|:---:|---|
| < 3.8 | ❌ |
| 3.8 | ✅ |
| 3.9 | ✅ |
| 3.10 | ✅ |
| 3.11 | ✅ |

# 💻 Installation of dependencies

Use the following command:

```bash
pip install -r requirements.txt
```

⚠️ Due to a [bug](https://github.com/PaulSec/API-dnsdumpster.com/pull/32) in the version **0.8** of the module [dnsdumpster](https://github.com/PaulSec/API-dnsdumpster.com), then, until the [version in pypi](https://pypi.org/project/dnsdumpster/) is the **0.8** then install the module using the following collection of command lines:

```bash
pip uninstall --yes dnsdumpster
pip install https://github.com/PaulSec/API-dnsdumpster.com/archive/master.zip
```

# 📡 Update of the "requirements.txt" file

Use the following command to use [pipreqs](https://github.com/bndr/pipreqs):

```bash
pipreqs --force .
```

# 📡 Update TLD list caching of the module "tldextract"

Use the following command from [here](https://github.com/john-kurkowski/tldextract#note-about-caching):

```bash
tldextract --update
```

# 🔑 API keys file

> **Note**: The script assume that an API key binded to the free version of the API is used of each service.

API keys are expected to be provided within an **INI** file having the following structure:

```ini
[API_KEYS]
;See https://www.shodan.io/
shodan=xxx
;See https://www.hybrid-analysis.com
hybrid-analysis=xxx
;See https://www.virustotal.com
virustotal=xxx
;See https://intelx.io/
intelx=xxx
;See https://azure.microsoft.com/en-us/try/cognitive-services/?api=search-api-v7
;See https://docs.microsoft.com/en-us/answers/questions/62385/please-help-me-to-find-the-process-to-get-ampampam.html
azure-cognitive-services-bing-web-search=xxx
;See https://buckets.grayhatwarfare.com/docs/api/v1
grayhatwarfare=xxx 
;See https://www.wappalyzer.com/api
wappalyzer=xxx
;See https://viewdns.info/api/
viewdns=xxx
```

# 👩‍💻 Usage examples

```bash
$ python wpr.py --help
usage: wpr.py [-h] -d DOMAIN_NAME [-a API_KEY_FILE] [-n NAME_SERVER] [-p HTTP_PROXY] [-s]

optional arguments:
  -h, --help      Show this help message and exit
  -a API_KEY_FILE Configuration INI file with all API keys 
                  (ex: conf.ini).
  -n NAME_SERVER  Name server to use for the DNS query 
                  (ex: 8.8.8.8).
  -p HTTP_PROXY   HTTP proxy to use for all HTTP call to differents services 
                  (ex: http://88.198.50.103:9080).
  -s              Save the result of the Google/Bing Dork searching for interesting files 
                  to the file 'filetype_dork_result.txt'.
  -t REQUEST_TIMEOUT  Delay in seconds allowed for a HTTP request to reply
                      before to fall in timeout (ex: 20) - min is 5 seconds.
 -m MOBILE_APP_STORE_COUNTRY_CODE
                      Country code to define in which store mobile app will be searched (ex: LU).                      

required arguments:
  -d DOMAIN_NAME  Domain to analyse (ex: righettod.eu).

$ python wpr.py -d righettod.eu
...

$ python wpr.py -d righettod.eu -n 8.8.8.8
...

$ python wpr.py -d righettod.eu -n 8.8.8.8 -m FR
...

$ python wpr.py -d righettod.eu -n 8.8.8.8 -t 30
...

$ python wpr.py -d righettod.eu -a api_keys.ini
...

$ python wpr.py -d righettod.eu -a api_keys.ini -n 8.8.8.8
...

$ python wpr.py -d righettod.eu -a api_keys.ini -n 8.8.8.8 -p http://5.196.132.126:3128
...

$ python wpr.py -d righettod.eu -a api_keys.ini -n 8.8.8.8 -p http://5.196.132.126:3128 -s
...
```

# 📺 Demonstration

https://user-images.githubusercontent.com/1573775/203140192-bf75a1a6-cddd-4f7c-8da9-5e931e6a3f21.mp4


