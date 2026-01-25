import re
from typing import Dict, List

class LogParser:
    """Parse various Log formats"""

    @staticmethod
    def extract_iocs(log: Dict) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from logs"""
        iocs = {
            'ip_addresses': [],
            'domains': [],
            'file_hashes': [],
            'urls': []
        }

        text = json.dumps(log)

        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs['ip_addresses'] = re.findall(ip_pattern, text)


        # Extract Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        iocs['domains'] = re.findall(domain_pattern, text)

        # Extract MD5/SHA256 Hashes
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b'
        iocs['file_hashes'] = re.findall(hash_pattern, text)

        return iocs