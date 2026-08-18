# Automated Threat Intelligence and Response Platform

This repository is a small, runnable Python reference implementation for processing security events. It reads JSON logs, extracts indicators of compromise (IOCs), optionally enriches IP addresses and file hashes, and evaluates YAML detection rules.

The bundled sample runs entirely offline. AbuseIPDB and VirusTotal are optional and are queried only when their API keys are present.

## What is implemented

- JSON, JSON-array, and newline-delimited JSON ingestion
- Normalization of common Sysmon process-creation fields
- Extraction of IP addresses, domains, MD5/SHA-256 hashes, and URLs
- Optional AbuseIPDB IP enrichment and VirusTotal file-hash enrichment
- An in-memory TTL cache for enrichment results
- YAML rules with `equals`, `contains`, and `regex` conditions
- Per-field count aggregation over a time window
- SSH brute-force and remote-administration-tool example rules
- A command-line interface that emits JSON alerts
- A runnable Docker image and Docker Compose service
- Unit and command-line tests

Rule `actions` are descriptive alert metadata. This project does not execute response actions or provide a web UI, API server, persistent database/cache, ticketing integrations, notifications, reports, or performance guarantees.

## Requirements

- Python 3.11 or newer
- Docker with the Compose plugin, only if using the container workflow

API keys are optional:

- `ABUSEIPDB_API_KEY`
- `VIRUSTOTAL_API_KEY`

## Quick start

```bash
git clone https://github.com/adanshul/Automated-Threat-Intelligence-and-Response-Platform.git
cd Automated-Threat-Intelligence-and-Response-Platform
python -m venv .venv
```

Activate the environment on macOS or Linux:

```bash
source .venv/bin/activate
```

Or activate it in PowerShell on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install the dependencies and run the bundled sample:

```bash
python -m pip install -r requirements.txt
python -m src.main --pretty
```

The sample processes six events and generates one SSH brute-force alert. To pass every path explicitly, run:

```bash
python -m src.main --log-file data/sample_logs/security_events.jsonl --rules config/detection_rules --pretty
```

Use `python -m src.main --help` to see all CLI options.

## Input format

The CLI accepts a JSON object, a JSON array of objects, or one JSON object per line. Generic events retain their existing fields. Events containing common Sysmon fields such as `Image`, `CommandLine`, and `Computer` are normalized to the detection schema.

An aggregation rule can look like this:

```yaml
name: "SSH Brute Force Detection"
id: "rule001"
severity: "high"
description: "Detects repeated failed SSH login attempts."
mitre_attack:
  - T1110.001
conditions:
  - field: "event_type"
    operator: "equals"
    value: "authentication_failure"
  - field: "protocol"
    operator: "equals"
    value: "ssh"
aggregation:
  field: "source_ip"
  count: 5
  timeframe: 300
actions:
  - type: "alert"
    priority: "high"
```

All conditions must match. Aggregation is performed separately for each value of the configured field.

## Optional threat-intelligence APIs

Set one or both environment variables before running the CLI. Without them, enrichment returns neutral `unknown` results and makes no network requests.

PowerShell:

```powershell
$env:ABUSEIPDB_API_KEY = "your-key"
$env:VIRUSTOTAL_API_KEY = "your-key"
python -m src.main --pretty
```

Direct use from Python is also supported:

```python
import os

from src.enrichment.threat_intel import ThreatIntelEnricher

enricher = ThreatIntelEnricher(
    {
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", ""),
        "virustotal": os.getenv("VIRUSTOTAL_API_KEY", ""),
    }
)
print(enricher.enrich_ip("8.8.8.8"))
```

## Docker

Build and run the one-shot sample pipeline:

```bash
docker compose up --build
```

Compose passes the optional API-key environment variables into the container. The service prints its JSON result and exits.

## Tests

After installing `requirements.txt`:

```bash
pytest
pytest --cov=src
```

## Repository layout

```text
.
├── config/detection_rules/       # Two example YAML rules
├── data/sample_logs/             # Offline JSONL sample
├── src/
│   ├── detection/                # Rule evaluation and aggregation
│   ├── enrichment/               # Optional API enrichment and MITRE helper
│   └── ingestion/                # JSON ingestion and IOC parsing
├── tests/                         # Unit and CLI tests
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
