"""Read JSON security events and normalize common Sysmon fields."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class LogCollector:
    """Collects and normalizes logs from various sources."""

    def __init__(self, config: Dict):
        self.config = config

    async def collect_logs(self, log_file: str) -> List[Dict[str, Any]]:
        """Read a JSON array, JSON object, or newline-delimited JSON file."""
        path = Path(log_file)
        text = path.read_text(encoding="utf-8")

        try:
            parsed = json.loads(text)
            raw_logs = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            raw_logs = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    raw_logs.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON on line {line_number} of {path}: {exc.msg}"
                    ) from exc

        if not all(isinstance(log, dict) for log in raw_logs):
            raise ValueError(f"Every event in {path} must be a JSON object")
        return [self._normalize(log) for log in raw_logs]

    async def collect_sysmon_logs(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse Sysmon logs into normalized format."""
        raw_logs = await self.collect_logs(log_file)
        return [self._normalize_sysmon(log.get("raw", log)) for log in raw_logs]

    def _normalize(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        sysmon_fields = {"Computer", "Image", "CommandLine", "ParentImage", "ProcessId"}
        if sysmon_fields.intersection(raw_log):
            return self._normalize_sysmon(raw_log)

        event = dict(raw_log)
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        event.setdefault("source", "generic_json")
        event["raw"] = raw_log
        return event

    def _normalize_sysmon(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a Sysmon process event to the common schema."""
        return {
            "timestamp": raw_log.get(
                "timestamp", raw_log.get("UtcTime", datetime.now(timezone.utc).isoformat())
            ),
            "event_type": "process_creation",
            "source": "sysmon",
            "host": raw_log.get("Computer", "unknown"),
            "user": raw_log.get("User", "unknown"),
            "process_name": raw_log.get("Image", ""),
            "command_line": raw_log.get("CommandLine", ""),
            "parent_process": raw_log.get("ParentImage", ""),
            "process_id": raw_log.get("ProcessId", ""),
            "source_ip": raw_log.get("SourceIp", ""),
            "raw": raw_log,
        }
