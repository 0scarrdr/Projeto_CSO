from ..core.incident import Incident
from ..utils.evidence import preserve
class IncidentAnalyzer:
    async def deep_analysis(self, incident: Incident) -> dict:
        path = preserve(incident)
        base = {"low": 0.2,"medium":0.5,"high":0.8,"critical":0.95}[incident.severity]
        bc = incident.attributes.get("business_criticality", 0.7)
        risk = min(1.0, base*0.6 + bc*0.4)
        return {"classification_confidence": min(1.0, base+0.05), "risk_score": round(risk,3), "evidence": path}
