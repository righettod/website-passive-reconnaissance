[![Requirements Status](https://requires.io/github/righettod/website-passive-reconnaissance/requirements.svg?branch=master)](https://requires.io/github/righettod/website-passive-reconnaissance/requirements/?branch=master) [![Known Vulnerabilities](https://snyk.io/test/github/righettod/website-passive-reconnaissance/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/righettod/website-passive-reconnaissance?targetFile=requirements.txt)


# Objectives

Script to automate, when possible, the **passive reconnaissance** performed on a website prior to an assessment (no direct hit on the target).

Also used to guide my reconnaissance phase by defining all steps (manual or automated) that must be mandatory performed.

# Requirements

Python >= 3.7

# Installation of dependencies

Use the following command:

```bash
$ pip install -r requirements.txt
```

# API keys file

API keys are expected to be provided within an INI file having the followign struture:

```ini
[API_KEYS]
shodan = xxx
```

# Usage examples

```bash
$ python --version
Python 3.7.5

$ python website_passive_recon.py --help
usage: website_passive_recon.py [-h] -d DOMAIN_NAME [-a API_KEY_FILE] [-n NAME_SERVER]
optional arguments:
  -h, --help       show this help message and exit
  -d DOMAIN_NAME   Domain to analyse (ex: www.righettod.eu).
  -a API_KEY_FILE  Configuration INI file with all API keys (ex: conf.ini).
  -n NAME_SERVER   Name server to use for the DNS query (ex: 8.8.8.8).

$ python website_passive_recon.py -d excellium.lu
...

$ python website_passive_recon.py -d excellium.lu -n 8.8.8.8
...

$ python website_passive_recon.py -d excellium.lu -a api_keys.ini
...

$ python website_passive_recon.py -d excellium.lu -a api_keys.ini -n 8.8.8.8
...
```
