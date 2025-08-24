import yaml
from pathlib import Path
from .orchestrator import ResponseOrchestrator

class PlaybookLibrary:
    def __init__(self, root: str|None=None):
        self.root = Path(root or Path(__file__).resolve().parent.parent / "playbooks")
    def select_playbook(self, incident) -> dict:
        filename = {
            "brute_force": "block_bruteforce.yml",
            "malware_alert": "quarantine.yml",
            "data_exfiltration": "block_exfiltration.yml",
            "network_anomaly": "investigate.yml",
            "policy_violation": "policy_violation.yml",
        }.get(incident.type, "investigate.yml")
        return yaml.safe_load((self.root / filename).read_text(encoding="utf-8"))

class AutomatedResponder:
    def __init__(self):
        self.playbooks = PlaybookLibrary()
        self.orchestrator = ResponseOrchestrator()
    async def execute_playbook(self, incident):
        playbook = self.playbooks.select_playbook(incident)
        return await self.orchestrator.execute(playbook, incident)
