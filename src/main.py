"""Command-line entry point for the local threat detection pipeline."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Sequence

import yaml

from src.detection.rule_engine import DetectionRuleEngine
from src.enrichment.threat_intel import ThreatIntelEnricher
from src.ingestion.log_collector import LogCollector
from src.ingestion.parsers import LogParser


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "sample_logs" / "security_events.jsonl"
DEFAULT_RULES_DIRECTORY = PROJECT_ROOT / "config" / "detection_rules"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Process JSON security events and evaluate YAML detection rules."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help=f"JSON or JSONL event file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES_DIRECTORY,
        help=f"directory containing YAML rules (default: {DEFAULT_RULES_DIRECTORY})",
    )
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    return parser


async def run_pipeline(log_file: Path, rules_directory: Path) -> Dict[str, Any]:
    collector = LogCollector({})
    events = await collector.collect_logs(str(log_file))
    rule_engine = DetectionRuleEngine(str(rules_directory))
    enricher = ThreatIntelEnricher(
        {
            "virustotal": os.getenv("VIRUSTOTAL_API_KEY", ""),
            "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", ""),
        }
    )

    alerts = []
    enriched_iocs: Dict[str, Dict[str, Any]] = {
        "ip_addresses": {},
        "file_hashes": {},
    }
    for event in events:
        iocs = LogParser.extract_iocs(event)
        event["iocs"] = iocs

        for ip_value in iocs["ip_addresses"]:
            if ip_value not in enriched_iocs["ip_addresses"]:
                enriched_iocs["ip_addresses"][ip_value] = enricher.enrich_ip(ip_value)
        for hash_value in iocs["file_hashes"]:
            if hash_value not in enriched_iocs["file_hashes"]:
                enriched_iocs["file_hashes"][hash_value] = enricher.enrich_hash(hash_value)

        alerts.extend(rule_engine.evaluate_event(event))

    return {
        "events_processed": len(events),
        "alerts_generated": len(alerts),
        "enriched_iocs": enriched_iocs,
        "alerts": alerts,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        result = asyncio.run(run_pipeline(args.log_file, args.rules))
    except (FileNotFoundError, OSError, ValueError, yaml.YAMLError) as exc:
        raise SystemExit(f"error: {exc}") from exc

    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
