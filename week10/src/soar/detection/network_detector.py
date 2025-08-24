import uuid
from datetime import datetime
from ..core.incident import Incident

class NetworkDetector:
    def classify(self, event: dict):
        if event.get("source") != "network": return None
        if event.get("anomaly_score", 0) > 0.9:
            return Incident(str(uuid.uuid4()), "network_anomaly", "high", "network", datetime.utcnow(), attributes=event)
        if event.get("dst_port") in (22,3389) and event.get("failed_attempts",0) > 50:
            return Incident(str(uuid.uuid4()), "brute_force", "high", "network", datetime.utcnow(), attributes=event)
        return None
