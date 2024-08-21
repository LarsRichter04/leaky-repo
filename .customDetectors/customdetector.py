import re

from detect_secrets.plugins.base import RegexBasedDetector



class CustomWrittenDetector(RegexBasedDetector):
    secret_type = 'CustomWrittenDetector'

    denylist = [
        re.compile(
            r'([A-Z]\!)+'
        ),
        re.compile(
            r'.{0,20}?(NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY).{0,20}?[\'\"].{10,120}[\'\"]'
        ),
    ]