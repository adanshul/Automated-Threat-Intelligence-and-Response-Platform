import yaml
import re
from typing import List, Dict
from datetime import datetime, timedata, timedelta
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

def _check_conditions(self, event: Dict, conditions: List[Dict]) -> bool:
    """Check if event matches all conditions."""
    for condition in conditions:
        field = condition['field']
        operator = condition['operator']

        if field not in event:
            return False
        
        event_value = event[field]

        if operator == 'equals':
            if event_value != condition['value']:
                return False
            
        elif operator == 'contains':
            values = condition.get('values', [condition.get('value')])
            if not any(val.lower() in str(event_value).lower() for val in values):
                return False
            
        elif operator == 'regex':
            if not re.search(condition['value'], str(event_value), re.IGNORECASE):
                return False
            
    return True

def _check_aggregation(self, event: Dict, rule: Dict) -> bool:
    """Check if aggregation threshold is met"""
    agg_config = rule['aggregation']
    field = agg_config['field']
    count_threshold = agg_config['count']
    timeframe = agg_config['timeframe']  # in seconds

    key = f"{rule['id']}:{event.get(field, 'unknown')}"

    # Add event to buffer 
    self.event_buffer[key].append({
        'timestamp': datetime.fromisoformat(event['timestamp']),
        'event': event
    })

    # Remove old events outside the timeframe
    cutoff_time = datetime.utcnow() - timedelta(seconds=timeframe)
    self.event_buffer[key] = [
        e for e in self.event_buffer[key] 
        if e['timestamp'] >= cutoff_time
    ]

    # Check if count threshold is met
    return len(self.event_buffer[key]) >= count_threshold

def _create_alert(self, event: Dict, rule: Dict) -> Dict:
    """Create an alert dictionary based on the triggered rule and event."""
    alert = {
            'alert_id': f"alert_{datetime.utcnow().timestamp()}",
            'timestamp': datetime.utcnow().isoformat(),
            'rule_name': rule['name'],
            'rule_id': rule['id'],
            'severity': rule['severity'],
            'description': rule['description'],
            'mitre_attack': rule.get('mitre_attack', []),
            'actions': rule.get('actions', []),
            'event': event
    }
    