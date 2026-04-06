![Test application running state](https://github.com/righettod/website-passive-reconnaissance/workflows/Test%20application%20running%20state/badge.svg) ![Audit python code with CodeQL](https://github.com/righettod/website-passive-reconnaissance/actions/workflows/codeql.yml/badge.svg?branch=master)

![MadeWitVSCode](https://img.shields.io/static/v1?label=Made%20with&message=VisualStudio%20Code&color=blue&?style=for-the-badge&logo=visualstudio)  ![AutomatedWith](https://img.shields.io/static/v1?label=Automated%20with&message=GitHub%20Actions&color=blue&?style=for-the-badge&logo=github) ![AuditedWith](https://img.shields.io/static/v1?label=Audited%20with&message=GitHub%20CodeQL&color=blue&?style=for-the-badge&logo=github)

# 🎯 Objectives

Script to automate, when possible, the **[passive reconnaissance](https://www.codecademy.com/article/passive-active-reconnaissance)** performed on a website prior to an assessment (no direct hit on the target).

Also used to guide a reconnaissance phase by defining all steps (manual or automated) that must be mandatory performed.

# 📦 Requirements

💬 Execution tested on the following 64 bits versions of Python via this [workflow](https://github.com/righettod/website-passive-reconnaissance/actions/workflows/pythonapp.yml) and this [script](ci.sh):

| Version | Supported? |
|:---:|---|
| < 3.12 | ❌ |
| 3.12 | ✅ |
| 3.13 | ✅ |
| 3.14 | ✅ |

# 💻 Installation

Use the following command:

```bash
pip install --no-cache git+https://github.com/righettod/website-passive-reconnaissance.git@v2
```

# 🔑 API keys file

> **Note**: The script assume that an API key binded to the free version of the API is used of each service.

API keys are expected to be provided within an **INI** file having the following structure:

```ini
[API_KEYS]
;See https://www.shodan.io/
shodan=xxx
;See https://intelx.io/
intelx=xxx
;See https://buckets.grayhatwarfare.com/docs/api/v1
grayhatwarfare=xxx 
;See https://viewdns.info/api/
viewdns=xxx
;See https://dnsdumpster.com/developer/
dnsdumpster=xxx
;See https://docs.leakix.net/docs/api/authentication/
leakix=xxx
```

# 👩‍💻 Usage examples

```bash
$ wpr --help                                                                                   
usage: wpr [-h] [-v] -d DOMAIN_NAME [-a API_KEY_FILE] [-n NAME_SERVER] [-t REQUEST_TIMEOUT] [-m MOBILE_APP_STORE_COUNTRY_CODE]

options:
  -h, --help            show this help message and exit
  -v                    show program's version number and exit  
  -a API_KEY_FILE       Configuration INI file with all API keys (ex: conf.ini).
  -n NAME_SERVER        Name server to use for the DNS query (ex: 8.8.8.8), default to the system defined one.
  -t REQUEST_TIMEOUT    Delay in seconds allowed for a HTTP request to reply before to fall in timeout (default to 240 seconds).
  -m MOBILE_APP_STORE_COUNTRY_CODE
                        Country code to define in which store mobile app will be searched (default to LU).

required arguments:
  -d DOMAIN_NAME        Domain to analyse (ex: righettod.eu).
```

```bash
wpr -d righettod.eu
wpr -d righettod.eu -n 8.8.8.8
wpr -d righettod.eu -n 8.8.8.8 -m FR
wpr -d righettod.eu -n 8.8.8.8 -t 30
wpr -d righettod.eu -a api_keys.ini
wpr -d righettod.eu -a api_keys.ini -n 8.8.8.8
```

# 📺 Demonstration

TODO

# 🧑‍💻 Migration to V2 & Development

## Choices

* The migration was performed with the help of [Claude Code](https://claude.com/product/claude-code).
* The following data providers were removed during the migration as data provided was not relevant (at least, it was a element noticed during the usage of the V1):
  * **Virus Total**: <https://www.virustotal.com>
  * **Hybrid Analysis**: <https://www.hybrid-analysis.com>
  * **Azure Cognitive Services Bing Web Search**: <https://azure.microsoft.com/en-us/try/cognitive-services/?api=search-api-v7>
* Support for web proxy as removed as it was never used  (at least, it was a element noticed during the usage of the V1), same for the option `-s`.

## Project

* It is configured to use [Visual Studio Code](https://code.visualstudio.com/) and a [workspace file](project.code-workspace) is provided.
* It use [uv](https://docs.astral.sh/uv/) to manage [the python project](pyproject.toml).
* OSINT data providers are now defined via a sub classe to allow to easlily add new ones.
* [CLAUDE.md file](CLAUDE.md) and other [Claude code related files](.claude/) are used to define the coding and security guidelines.
* Use the following command to run the project locally:

```bash
cd src/wpr
uv run main.py -d righettod.eu
```
