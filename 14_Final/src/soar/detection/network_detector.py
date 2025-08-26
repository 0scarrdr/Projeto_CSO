import uuid
from datetime import datetime
from ..core.incident import Incident

class NetworkDetector:
    def classify(self, event: dict):
        if event.get("source") != "network": return None
        # Anomalias gerais
        if event.get("anomaly_score", 0) > 0.9:
            return Incident(str(uuid.uuid4()), "network_anomaly", "high", "network", datetime.utcnow(), attributes=event)
        # Brute force em SSH/RDP
        if event.get("dst_port") in (22,3389) and event.get("failed_attempts",0) > 50:
            return Incident(str(uuid.uuid4()), "brute_force", "high", "network", datetime.utcnow(), attributes=event)
        # Deteção de scan de portas
        if event.get("scan_detected", False):
            return Incident(str(uuid.uuid4()), "port_scan", "medium", "network", datetime.utcnow(), attributes=event)
        # Exfiltração de dados
        if event.get("exfiltration_bytes", 0) > 10000000:
            return Incident(str(uuid.uuid4()), "data_exfiltration", "critical", "network", datetime.utcnow(), attributes=event)
        # Ataques comuns
        if event.get("attack_type") == "dos":
            return Incident(str(uuid.uuid4()), "dos_attack", "high", "network", datetime.utcnow(), attributes=event)
        if event.get("attack_type") == "sql_injection":
            return Incident(str(uuid.uuid4()), "sql_injection", "high", "network", datetime.utcnow(), attributes=event)
        return None
