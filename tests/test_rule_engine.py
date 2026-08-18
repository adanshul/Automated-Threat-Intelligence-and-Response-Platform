from pathlib import Path

from src.detection.rule_engine import DetectionRuleEngine


def write_rule(directory: Path, aggregation: bool = False) -> None:
    aggregation_yaml = (
        """
aggregation:
  field: source_ip
  count: 3
  timeframe: 60
"""
        if aggregation
        else ""
    )
    (directory / "test.yaml").write_text(
        f"""
name: Test rule
id: test-rule
severity: high
description: A test rule
conditions:
  - field: event_type
    operator: equals
    value: authentication_failure
  - field: message
    operator: regex
    value: "ssh.*failed"
{aggregation_yaml}
""",
        encoding="utf-8",
    )


def test_non_aggregated_rule_only_alerts_on_match(tmp_path: Path) -> None:
    write_rule(tmp_path)
    engine = DetectionRuleEngine(str(tmp_path))

    matching = {"event_type": "authentication_failure", "message": "SSH login failed"}
    unrelated = {"event_type": "login_success", "message": "SSH login succeeded"}

    alerts = engine.evaluate_event(matching)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "test-rule"
    assert engine.evaluate_event(unrelated) == []


def test_aggregation_alerts_only_after_threshold_for_same_group(tmp_path: Path) -> None:
    write_rule(tmp_path, aggregation=True)
    engine = DetectionRuleEngine(str(tmp_path))
    base = {
        "event_type": "authentication_failure",
        "message": "ssh password failed",
        "source_ip": "203.0.113.20",
    }

    assert engine.evaluate_event({**base, "timestamp": "2026-01-01T00:00:00Z"}) == []
    assert engine.evaluate_event({**base, "timestamp": "2026-01-01T00:00:20Z"}) == []
    alerts = engine.evaluate_event({**base, "timestamp": "2026-01-01T00:00:40Z"})

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"


def test_aggregation_expires_old_events(tmp_path: Path) -> None:
    write_rule(tmp_path, aggregation=True)
    engine = DetectionRuleEngine(str(tmp_path))
    base = {
        "event_type": "authentication_failure",
        "message": "ssh password failed",
        "source_ip": "203.0.113.20",
    }

    engine.evaluate_event({**base, "timestamp": "2026-01-01T00:00:00Z"})
    engine.evaluate_event({**base, "timestamp": "2026-01-01T00:00:20Z"})
    alerts = engine.evaluate_event({**base, "timestamp": "2026-01-01T00:02:00Z"})

    assert alerts == []
