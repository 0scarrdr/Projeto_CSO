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

    EXTRA_PATTERNS = [
        (re.compile(r"failed password|authentication failure", re.I), ("auth_failure", "medium")),
        (re.compile(r"Accepted password|session opened", re.I), ("auth_success", "low")),
        (re.compile(r"sshd.*connection closed", re.I), ("ssh_disconnect", "low")),
        (re.compile(r"sshd.*connection established", re.I), ("ssh_connect", "low")),
    ]

    def classify(self, event: dict):
        if event.get("source") != "log": return None
        line = event.get("message", "")
        # Regras principais
        for rx, (itype, sev) in self.PATTERNS:
            if rx.search(line):
                return Incident(str(uuid.uuid4()), itype, sev, "log", datetime.utcnow(), attributes=event)
        # Regras extra
        for rx, (itype, sev) in self.EXTRA_PATTERNS:
            if rx.search(line):
                return Incident(str(uuid.uuid4()), itype, sev, "log", datetime.utcnow(), attributes=event)
        return None
