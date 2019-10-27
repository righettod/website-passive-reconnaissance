[![Requirements Status](https://requires.io/github/righettod/website-passive-reconnaissance/requirements.svg?branch=master)](https://requires.io/github/righettod/website-passive-reconnaissance/requirements/?branch=master) [![Known Vulnerabilities](https://snyk.io/test/github/righettod/website-passive-reconnaissance/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/righettod/website-passive-reconnaissance?targetFile=requirements.txt)


# Objectives

Script to automate, when possible, the **passive reconnaissance** performed a website prior to an assessment (no direct hit on the target).

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
```

```bash
$ python website_passive_recon.py -d excellium.lu
***********************
* EXCELLIUM.LU
***********************
[CONF] System default name server used for all DNS query.
[DNS] Extract the IP V4/V6 addresses...
217.31.74.131
[DNS] Extract the aliases...
[RIPE] Extract the owner information of the IP addresses...
217.31.74.131
  inetnum = 217.31.74.128 - 217.31.74.143
  netname = CEGECOM-EXCELLIUM
  descr = Excellium
  descr = Projekt W.11.102072.3
  country = LU
  admin-c = CG9318-RIPE
  tech-c = CG9318-RIPE
  status = ASSIGNED PA
  mnt-by = CEGECOM-LU-MNT
  created = 2016-01-18T09:07:44Z
  last-modified = 2016-01-18T09:07:44Z
  source = RIPE
[SHODAN] Extract the information of the IP addresses and domain...
Skipped because no API key file was specified!
[HACKERTARGET] Extract hosts shared by each IP address...
217.31.74.131
  excellium.lu
  eyeguard.lu
  in-relay.monitoring.eyeguard.lu
  monitoring.eyeguard.lu
  out-relay.monitoring.eyeguard.lu
  www.excellium.lu
[NETCRAFT] Provide the URL to report for the domain and IP addresses...
No API provided and browser required, so, use the following URL from a browser:
  https://toolbar.netcraft.com/site_report?url=excellium.lu
  https://toolbar.netcraft.com/site_report?url=217.31.74.131
[GOOGLE] Provide the URL for dork for the domain...
Use the following URL from a browser:
  https://www.google.com/search?q=site%3Aexcellium.lu&oq=site%3Aexcellium.lu
Done.
```

```bash
$ python website_passive_recon.py -d excellium.lu -a api_keys.ini -n 8.8.8.8
***********************
* EXCELLIUM.LU
***********************
[CONF] API key file 'api_keys.ini' loaded.
[CONF] Name server 8.8.8.8 used for all DNS query.
[DNS] Extract the IP V4/V6 addresses...
217.31.74.131
[DNS] Extract the aliases...
[RIPE] Extract the owner information of the IP addresses...
217.31.74.131
  inetnum = 217.31.74.128 - 217.31.74.143
  netname = CEGECOM-EXCELLIUM
  descr = Excellium
  descr = Projekt W.11.102072.3
  country = LU
  admin-c = CG9318-RIPE
  tech-c = CG9318-RIPE
  status = ASSIGNED PA
  mnt-by = CEGECOM-LU-MNT
  created = 2016-01-18T09:07:44Z
  last-modified = 2016-01-18T09:07:44Z
  source = RIPE
[SHODAN] Extract the information of the IP addresses and domain...
excellium.lu
  Search with filter using the API with a free tier API key is not allowed, so, use the following URL from a browser:
  https://www.shodan.io/search?query=hostname%3Aexcellium.lu
217.31.74.131
  Last update = 2019-10-20T04:02:01.192006
  ISP = Cegecom S.A.
  Organization = Cegecom S.A.
  Hostnames = ['217.31.74.135.DSL.CEGECOM.LU']
  Ports = [8008, 22]
[HACKERTARGET] Extract hosts shared by each IP address...
217.31.74.131
  excellium.lu
  eyeguard.lu
  in-relay.monitoring.eyeguard.lu
  monitoring.eyeguard.lu
  out-relay.monitoring.eyeguard.lu
  www.excellium.lu
[NETCRAFT] Provide the URL to report for the domain and IP addresses...
No API provided and browser required, so, use the following URL from a browser:
  https://toolbar.netcraft.com/site_report?url=excellium.lu
  https://toolbar.netcraft.com/site_report?url=217.31.74.131
[GOOGLE] Provide the URL for dork for the domain...
Use the following URL from a browser:
  https://www.google.com/search?q=site%3Aexcellium.lu&oq=site%3Aexcellium.lu
Done.
```
