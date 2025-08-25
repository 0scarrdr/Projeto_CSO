import re, uuid
from datetime import datetime
from ..core.incident import Incident

class LogDetector:
    PATTERNS = [
        (re.compile(r"failed login.*root", re.I), ("brute_force", "high")),
        (re.compile(r"(malware|ransomware) detected", re.I), ("malware_alert", "critical")),
        (re.compile(r"policy violation", re.I), ("policy_violation", "medium")),
        (re.compile(r"suspicious exfiltration", re.I), ("data_exfiltration", "critical")),
    ]
    def classify(self, event: dict):
        if event.get("source") != "log": return None
        line = event.get("message", "")
        for rx, (itype, sev) in self.PATTERNS:
            if rx.search(line):
                return Incident(str(uuid.uuid4()), itype, sev, "log", datetime.utcnow(), attributes=event)
        return None
