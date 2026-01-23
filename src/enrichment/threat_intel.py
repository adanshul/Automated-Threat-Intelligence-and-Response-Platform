import requests
import hashlib
from typing import Dict, Optional
from datetime import datetime, timedelta
import time

class ThreatIntelEnricher:
    """Enrich IOCs with threat intelligence from multiple sources"""

    def __init__(self, api_keys: Dict, cache_manager):
        self.vt_api_key = api_keys.get('virustotal')
        self.abuseipdb_key = api_keys.get('abuseipdb')
        self.cache = cache_manager
        self.rate_limits = {'vt' : 0. 'abuseipdb' : 0}


    def enrich_ip(self, ip_address: str) -> Dict:
        """Enrich IP address with threat Intelligence"""

        cached = self.cache.get(f"ip:{ip_address}")
        if cached:
            return cached
        
        enrichment = {
            'ip': ip_address,
            'reputation_score': 0,
            'threat_level': 'unknown',
            'tags': [],
            'sources': {}
        }

        # AbuseIPDB enrichment
        abuseipdb_data = self._query_abuseipdb(ip_address)
        if abuseipdb_data:
            enrichment['sources']['abuseipdb'] = abuseipdb_data
            enrichment['reputation_score'] = abuseipdb_data.get('abuseConfidenceScore', 0)

            # Determine threat level
            if enrichment['reputation_score'] >= 75:
                enrichment['threat_level'] = 'high'
            elif enrichment['reputation_score'] >= 50:
                enrichment['threat_level'] = 'medium'
            else:
                enrichment['threat_level'] = 'low'

            # Cache for 1 hour
            self.cache.set(f"ip:{ip_address}", enrichment, ttl=3600)
            return enrichment
        

        def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
            """Query AbuseIPDB API"""
            if not self.abuseipdb_key:
                return None
            
            self._rate_limit_check('abuseipdb')

            url  = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Key': self.abuseipdb_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}

            try:
                response = requests.get(url, headers==headers, params=params, timeout=5)
                if response.status_code == 200:
                    return response.json().get('data', {})
            except requests.RequestExceprtion as e:
                print(f"AbuseIPDB query failed: {e}")

            return None
        
        def enrich_hash(self, file_hash: str ) -> Dict:
            """Enrich file hash with VirusTotal data"""

            cached = self.cache.get(f"hash:{file_hash}")
            if cached:
                return cached
            
            enrichment = {
                'hash': file_hash,
                'malicious': False,
                'detections': 0,
                'total_engines': 0,
                'tags': []
            }

            vt_data = self._query_virustotal(file_hash)
            if vt_data:
                stats = vt_data.get('attributes', {}).get('last_analysis_stats', {})
                enrichment['detections'] = stats.get('malicious', 0)
                enrichment['total_engines'] = sum(stats.values())
                enrichment['malicious'] = enrichment['detections'] > 3
                enrichment['sources'] = {'virustotal': vt_data}

            self.cache.set(f"hash:{file_hash}", enrichment, ttl=86400)
            return enrichment