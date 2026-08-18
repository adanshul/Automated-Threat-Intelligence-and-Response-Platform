import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        [
            "--log-file",
            "data/sample_logs/security_events.jsonl",
            "--rules",
            "config/detection_rules",
            "--pretty",
        ],
    ],
)
def test_readme_cli_commands_execute(arguments: list[str]) -> None:
    environment = os.environ.copy()
    environment["ABUSEIPDB_API_KEY"] = ""
    environment["VIRUSTOTAL_API_KEY"] = ""

    completed = subprocess.run(
        [sys.executable, "-m", "src.main", *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["events_processed"] == 6
    assert result["alerts_generated"] == 1
    assert result["alerts"][0]["rule_id"] == "rule001"
