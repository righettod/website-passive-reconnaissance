import argparse
import configparser
import time

from wpr.constants import DEFAULT_CALL_TIMEOUT, MOBILE_APP_STORE_COUNTRY_STORE_CODE

if __name__ == "__main__":
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
    if args.api_key_file is not None:
        api_key_config.read(args.api_key_file)
    default_request_timeout = DEFAULT_CALL_TIMEOUT
    if args.request_timeout is not None and args.request_timeout > 1:
        default_request_timeout = args.request_timeout
    default_name_server = None
    if args.name_server is not None:
        default_name_server = args.name_server
    default_mobile_app_store_country_store_code = MOBILE_APP_STORE_COUNTRY_STORE_CODE
    if args.mobile_app_store_country_code != MOBILE_APP_STORE_COUNTRY_STORE_CODE:
        default_mobile_app_store_country_store_code = args.mobile_app_store_country_code
