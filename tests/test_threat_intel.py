from typing import Any

from src.enrichment.threat_intel import ThreatIntelEnricher


class FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.payload


class FakeSession:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((url, kwargs))
        return FakeResponse(self.payload)


class FailingSession:
    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        raise AssertionError("an API call was made without a configured key")


def test_no_api_key_returns_neutral_result_without_network() -> None:
    enricher = ThreatIntelEnricher(session=FailingSession())

    assert enricher.enrich_ip("203.0.113.10")["threat_level"] == "unknown"
    assert enricher.enrich_hash("a" * 64)["detections"] == 0


def test_abuseipdb_result_is_scored_and_cached() -> None:
    session = FakeSession({"data": {"abuseConfidenceScore": 82, "countryCode": "US"}})
    enricher = ThreatIntelEnricher(
        {"abuseipdb": "test-key"}, session=session, request_interval=0
    )

    first = enricher.enrich_ip("8.8.8.8")
    second = enricher.enrich_ip("8.8.8.8")

    assert first["threat_level"] == "high"
    assert first["reputation_score"] == 82
    assert second == first
    assert len(session.calls) == 1
    assert session.calls[0][1]["headers"]["Key"] == "test-key"


def test_virustotal_stats_are_summarized() -> None:
    session = FakeSession(
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "harmless": 68},
                    "tags": ["peexe"],
                }
            }
        }
    )
    enricher = ThreatIntelEnricher(
        {"virustotal": "test-key"}, session=session, request_interval=0
    )

    result = enricher.enrich_hash("a" * 64)

    assert result["malicious"] is True
    assert result["detections"] == 2
    assert result["total_engines"] == 70
    assert result["tags"] == ["peexe"]
