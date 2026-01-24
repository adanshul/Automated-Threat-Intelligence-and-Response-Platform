import json
from pyclbr import Class
from typing import Dict, List

class MITREMapper:
    """Map detected beahaviours to MITRE ATT&CK techniques"""

    def __init__(self, attack_data_file: str):
        with open('attack_data_file', 'r') as f:
            self.attack_data = json.load(f)
        self.technique_map = self._build_technique_map()

    def _build_technique_map(self) -> Dict:
        """Build mapping of behaviours to MITRE techniques"""
        return {
            'powershell_encoded': ['T1059.001', 'T1027'],
            'credential_dumping': ['T1003'],
            'lateral_movement_smb': ['T1021.002'],
            'persistence_registry': ['T1547.001'],
            'process_injection': ['T1055'],
            'scheduled_task': ['T1053.005'],
        }

    def map_event(self, event: Dict) -> List[str]:
        """Map an event to MITRE ATT&CK techniques"""
        techniques = []

        # Check command line for Powershell encoding
        if 'command_line' in event:
            cmd = event['command_line'].lower()
            if 'powershell' in cmd and ('-enc' in cmd or '-encodedcommand' in cmd):
                techniques.extend(self.technique_map['powershell_encoded'])

            if 'mimikatz' in cmd or 'sekurlsa' in cmd:
                techniques.extend(self.technique_map['credential_dumping'])

            if 'schtasks' in cmd or 'at.exe' in cmd:
                techniques.extend(self.technique_map['scheduled_task'])

            return list(set(techniques))
        
    def get_technique_details(self, technique_id: str) -> Dict:
        """Get details for a specific MITRE technique"""
        for technique in self.attack_data.get('techniques', []):
            if technique.get('id') == technique_id:
                return {
                    'id': technique_id,
                    'name': technique.get('name'),
                    'tactic': technique.get('tactic'),
                    'description': technique.get('description')
                }
        return {}    