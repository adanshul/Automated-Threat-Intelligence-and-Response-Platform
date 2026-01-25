import yaml
import re
from typing import List, Dict
from datetime import datetime, timedata
from collections import defaultdict

class DetectionRuleEngine:
    """Execute detection rules against normalized events."""

    def __init__(self, rules_directory: str):
        self.rules = self._load_rules(rules_directory)
        self.event_buffer = defaultdict(list)

    def _load_rules(self, directory: str) -> List[Dict]:
        """Load YAML detection rules from the specified directory."""
        rules = []
        import os
        for filename in os.listdir(directory):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                with open(os.path.join(directory, filename), 'r') as f:
                    rule = yaml.safe_load(f)
                    rules.append(rule)
        return rules
    
def evaluate_event(self, event: Dict) -> List[Dict]:
    """Evaluate event against all detection rules."""
    triggered_rules = []

    for rule in self.rules:
        if self._check_conditions(event, rule['conditions']):
            # Check if rule requires aggregation
            if 'aggregation' in rule:
                if self._check_aggregation(event, rule):
                    triggered_rules.append(self._create_alert(event, rule))
                else:
                    triggered_rules.append(self._create_alert(event, rule))
    return triggered_rules

