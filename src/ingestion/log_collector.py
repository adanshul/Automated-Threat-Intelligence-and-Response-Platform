import json
import asyncio
from typing import List, Dict
from datetime import datetime
import logging

Class LogCollector:
    """Collects and normalizes logs from various sources."""
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)

    async def collect_sysmon_logs(self, log_file: str) -> List[Dict]:
        """Parse Sysmon logs into normalized format."""
        normalized_logs = []

        with open(log_file, 'r') as f:
            for line in f:
                try:
                    raw_log = json.loads(line)
                    normalized = self._normalize_sysmon(raw_log)
                    normalized_logs.append(normalized)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse log: {line}")

        return normalized_logs
    def _normalize_sysmon(self, raw_log: Dict) -> Dict:
        """Normalize sysmon log to common schema"""
        return{
            'timestamp': log.get('timestamp', datetime.utcnow().isoformat()),
            'event_type': 'process_creation',
            'source': 'sysmon',
            'host': log.get('Computer', 'unknown'),
            'user': log.get('User', 'unknown'),
            'process_name': log.get('Image', ''),
            'command_line': log.get('CommandLine', ''),
            'parent_process': log.get('ParentImage', ''),
            'process_id': log.get('ProcessId', ''),
            'ip_address': log.get('SourceIp', ''),
            'raw': log
        }