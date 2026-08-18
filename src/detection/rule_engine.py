"""YAML detection rule evaluation."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

import yaml


class DetectionRuleEngine:
    """Execute detection rules against normalized events."""

    def __init__(self, rules_directory: str):
        self.rules = self._load_rules(rules_directory)
        self.event_buffer: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def _load_rules(self, directory: str) -> List[Dict[str, Any]]:
        """Load YAML detection rules from the specified directory."""
        rules_path = Path(directory)
        if not rules_path.is_dir():
            raise FileNotFoundError(f"Rules directory does not exist: {rules_path}")

        rules: List[Dict[str, Any]] = []
        for filename in sorted((*rules_path.glob("*.yaml"), *rules_path.glob("*.yml"))):
            with filename.open("r", encoding="utf-8") as rule_file:
                rule = yaml.safe_load(rule_file)
            if rule is None:
                continue
            self._validate_rule(rule, filename)
            rules.append(rule)
        return rules

    @staticmethod
    def _validate_rule(rule: Any, filename: Path) -> None:
        if not isinstance(rule, dict):
            raise ValueError(f"Rule in {filename} must be a mapping")

        required = {"name", "id", "severity", "description", "conditions"}
        missing = sorted(required - rule.keys())
        if missing:
            raise ValueError(f"Rule in {filename} is missing: {', '.join(missing)}")
        if not isinstance(rule["conditions"], list) or not rule["conditions"]:
            raise ValueError(f"Rule in {filename} must have at least one condition")

        for condition in rule["conditions"]:
            if not isinstance(condition, dict):
                raise ValueError(f"Every condition in {filename} must be a mapping")
            operator = condition.get("operator")
            if operator not in {"equals", "contains", "regex"}:
                raise ValueError(f"Unsupported operator {operator!r} in {filename}")
            if "field" not in condition:
                raise ValueError(f"Condition without a field in {filename}")
            if operator == "regex":
                try:
                    re.compile(condition["value"])
                except (KeyError, TypeError, re.error) as exc:
                    raise ValueError(f"Invalid regex condition in {filename}: {exc}") from exc
            elif operator == "equals" and "value" not in condition:
                raise ValueError(f"Equals condition without a value in {filename}")
            elif operator == "contains" and not (
                "value" in condition or "values" in condition
            ):
                raise ValueError(f"Contains condition without a value in {filename}")

        if "aggregation" in rule:
            aggregation = rule["aggregation"]
            if not isinstance(aggregation, dict):
                raise ValueError(f"Aggregation in {filename} must be a mapping")
            for key in ("field", "count", "timeframe"):
                if key not in aggregation:
                    raise ValueError(f"Aggregation in {filename} is missing {key!r}")
            try:
                is_positive = aggregation["count"] >= 1 and aggregation["timeframe"] >= 1
            except TypeError as exc:
                raise ValueError(
                    f"Aggregation count and timeframe must be numeric in {filename}"
                ) from exc
            if not is_positive:
                raise ValueError(
                    f"Aggregation count and timeframe must be positive in {filename}"
                )

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate one event against every loaded rule."""
        triggered_rules: List[Dict[str, Any]] = []
        for rule in self.rules:
            if not self._check_conditions(event, rule["conditions"]):
                continue
            if "aggregation" in rule and not self._check_aggregation(event, rule):
                continue
            triggered_rules.append(self._create_alert(event, rule))
        return triggered_rules

    def _check_conditions(
        self, event: Dict[str, Any], conditions: List[Dict[str, Any]]
    ) -> bool:
        """Return true when every condition matches the event."""
        for condition in conditions:
            field = condition["field"]
            if field not in event:
                return False

            operator = condition["operator"]
            event_value = event[field]
            if operator == "equals" and event_value != condition.get("value"):
                return False
            if operator == "contains":
                values = condition.get("values")
                if values is None:
                    values = [condition.get("value")]
                if not any(
                    value is not None
                    and str(value).lower() in str(event_value).lower()
                    for value in values
                ):
                    return False
            if operator == "regex" and not re.search(
                condition["value"], str(event_value), re.IGNORECASE
            ):
                return False
        return True

    def _check_aggregation(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Track matching events and return whether the threshold is met."""
        aggregation = rule["aggregation"]
        group_value = event.get(aggregation["field"], "unknown")
        key = f"{rule['id']}:{group_value}"
        event_time = self._parse_timestamp(event.get("timestamp"))
        self.event_buffer[key].append({"timestamp": event_time, "event": event})

        cutoff = event_time - timedelta(seconds=aggregation["timeframe"])
        self.event_buffer[key] = [
            buffered
            for buffered in self.event_buffer[key]
            if cutoff <= buffered["timestamp"] <= event_time
        ]
        return len(self.event_buffer[key]) >= aggregation["count"]

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if value is None:
            return datetime.now(timezone.utc)
        if isinstance(value, datetime):
            parsed = value
        else:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _create_alert(event: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
        """Create an alert dictionary for a triggered rule."""
        return {
            "alert_id": f"alert_{uuid4().hex}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule_name": rule["name"],
            "rule_id": rule["id"],
            "severity": rule["severity"],
            "description": rule["description"],
            "mitre_attack": rule.get("mitre_attack", []),
            "actions": rule.get("actions", []),
            "event": event,
        }
