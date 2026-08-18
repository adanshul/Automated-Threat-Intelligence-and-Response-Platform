import json
import re
from ipaddress import ip_address
from typing import Any, Dict, List


class LogParser:
    """Extract indicators of compromise from normalized log events."""

    @staticmethod
    def extract_iocs(log: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract indicators of compromise from a log event."""
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "file_hashes": [],
            "urls": [],
        }

        text = json.dumps(log)

        # Extract IP addresses
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        candidates = re.findall(ip_pattern, text)
        iocs["ip_addresses"] = list(
            dict.fromkeys(candidate for candidate in candidates if _is_ip(candidate))
        )

        # Extract domains
        domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        iocs["domains"] = list(dict.fromkeys(re.findall(domain_pattern, text)))

        # Extract MD5/SHA-256 hashes
        hash_pattern = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b"
        iocs["file_hashes"] = list(dict.fromkeys(re.findall(hash_pattern, text)))

        url_pattern = r'https?://[^\s"<>]+'
        iocs["urls"] = list(dict.fromkeys(re.findall(url_pattern, text)))

        return iocs


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True
