"""
Incident analysis module: calculates risk score and enriches with CTI.
"""

import hashlib
from soar.integrations.cti import CTIClient
from soar.utils.logging import get_logger
from ..utils.evidence import EvidenceStore
import traceback


logger = get_logger(__name__)


class IncidentAnalyzer:
    def __init__(self):
        self.evidence_store = EvidenceStore()
        self.cti = CTIClient()

    def _calc_risk(self, incident: dict) -> float:
        severities = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
        base = severities.get(incident.get("severity", "low"), 0.1)
        context = 0.2 if incident.get("business_critical") else 0.0
        return round(min(base + context, 1.0), 2)

    def _enrich_cti(self, incident: dict) -> dict:
        ip = incident.get("src_ip")
        domain = incident.get("domain")
        if ip:
            incident["cti"] = self.cti.check_ip(ip)
        elif domain:
            incident["cti"] = self.cti.check_domain(domain)
        return incident

    def analyze(self, incident: dict) -> dict:
        try:
            incident["risk_score"] = self._calc_risk(incident)
            incident = self._enrich_cti(incident)
            self.evidence_store.preserve(incident)
            return incident
        except Exception as e:
            logger = get_logger(__name__)
            logger.error(f"Erro em analyze: {e}\nTraceback:\n{traceback.format_exc()}")
            raise
            logger.error(f"Erro em analyze: {e}\nTraceback:\n{traceback.format_exc()}")
            raise
        logger.info(f"Incidente analisado {incident.get('id')} risco={incident['risk_score']}")
        return incident
