"""
Contains constants and configuration items. All time units are in seconds.
"""
import os

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
MOBILE_APP_STORE_COUNTRY_STORE_CODE = "LU"  # Luxembourg
DEFAULT_CALL_TIMEOUT = 240
HEADER_LENGTH = 50
MAX_CALL_TENTATIVES = 4
RETRY_WAIT_DELAY = 4
TERMINAL_WIDTH = os.get_terminal_size().columns
