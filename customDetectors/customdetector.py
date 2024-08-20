import re

from detect_secrets.plugins.base import RegexBasedDetector



class CustomWrittenDetector(RegexBasedDetector):
    """Scans for Basic Auth formatted URIs."""
    secret_type = 'CustomWrittenDetector'

    denylist = [
        re.compile(
            r'([A-Z]\!)+'
        ),
    ]