"""Optional threat-intelligence enrichment clients.

No API call is made unless its corresponding key is configured.  API failures are
logged and represented by a neutral result so that the detection pipeline can
continue processing local logs.
"""

from __future__ import annotations

import logging
import time
from copy import deepcopy
from typing import Any, Dict, Optional, Protocol

import requests


LOGGER = logging.getLogger(__name__)


class Cache(Protocol):
    """Minimal cache interface used by :class:`ThreatIntelEnricher`."""

    def get(self, key: str) -> Optional[Dict[str, Any]]: ...

    def set(self, key: str, value: Dict[str, Any], ttl: int) -> None: ...


class MemoryTTLCache:
    """Small in-process TTL cache suitable for CLI runs and tests."""

    def __init__(self) -> None:
        self._values: Dict[str, tuple[float, Dict[str, Any]]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        cached = self._values.get(key)
        if cached is None:
            return None

        expires_at, value = cached
        if expires_at <= time.monotonic():
            self._values.pop(key, None)
            return None
        return deepcopy(value)

    def set(self, key: str, value: Dict[str, Any], ttl: int) -> None:
        self._values[key] = (time.monotonic() + ttl, deepcopy(value))


class ThreatIntelEnricher:
    """Enrich IP addresses and file hashes with optional external APIs."""

    def __init__(
        self,
        api_keys: Optional[Dict[str, str]] = None,
        cache_manager: Optional[Cache] = None,
        session: Optional[requests.Session] = None,
        request_interval: float = 1.0,
    ) -> None:
        api_keys = api_keys or {}
        self.vt_api_key = api_keys.get("virustotal")
        self.abuseipdb_key = api_keys.get("abuseipdb")
        self.cache = cache_manager or MemoryTTLCache()
        self.session = session or requests.Session()
        self.request_interval = max(0.0, request_interval)
        self.rate_limits = {"vt": 0.0, "abuseipdb": 0.0}

    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """Return AbuseIPDB context for an IP, or a neutral offline result."""
        cache_key = f"ip:{ip_address}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        enrichment: Dict[str, Any] = {
            "ip": ip_address,
            "reputation_score": 0,
            "threat_level": "unknown",
            "tags": [],
            "sources": {},
        }

        abuseipdb_data = self._query_abuseipdb(ip_address)
        if abuseipdb_data is not None:
            score = int(abuseipdb_data.get("abuseConfidenceScore", 0) or 0)
            enrichment["sources"]["abuseipdb"] = abuseipdb_data
            enrichment["reputation_score"] = score
            enrichment["threat_level"] = (
                "high" if score >= 75 else "medium" if score >= 50 else "low"
            )

        self.cache.set(cache_key, enrichment, ttl=3600)
        return enrichment

    def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """Return VirusTotal analysis statistics for a file hash."""
        cache_key = f"hash:{file_hash.lower()}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        enrichment: Dict[str, Any] = {
            "hash": file_hash,
            "malicious": False,
            "detections": 0,
            "total_engines": 0,
            "tags": [],
            "sources": {},
        }

        vt_data = self._query_virustotal_hash(file_hash)
        if vt_data is not None:
            attributes = vt_data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            numeric_stats = [value for value in stats.values() if isinstance(value, int)]
            enrichment["detections"] = int(stats.get("malicious", 0) or 0)
            enrichment["total_engines"] = sum(numeric_stats)
            enrichment["malicious"] = enrichment["detections"] > 0
            enrichment["tags"] = list(attributes.get("tags", []))
            enrichment["sources"]["virustotal"] = vt_data

        self.cache.set(cache_key, enrichment, ttl=86400)
        return enrichment

    def _query_abuseipdb(self, ip_address: str) -> Optional[Dict[str, Any]]:
        if not self.abuseipdb_key:
            return None

        self._rate_limit_check("abuseipdb")
        try:
            response = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip_address, "maxAgeInDays": "90"},
                timeout=5,
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except (requests.RequestException, ValueError, TypeError) as exc:
            LOGGER.warning("AbuseIPDB query failed for %s: %s", ip_address, exc)
            return None

    def _query_virustotal_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        if not self.vt_api_key:
            return None

        self._rate_limit_check("vt")
        try:
            response = self.session.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self.vt_api_key},
                timeout=5,
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except (requests.RequestException, ValueError, TypeError) as exc:
            LOGGER.warning("VirusTotal query failed for %s: %s", file_hash, exc)
            return None

    def _rate_limit_check(self, source: str) -> None:
        now = time.monotonic()
        elapsed = now - self.rate_limits[source]
        if elapsed < self.request_interval:
            time.sleep(self.request_interval - elapsed)
        self.rate_limits[source] = time.monotonic()
