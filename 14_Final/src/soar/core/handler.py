import asyncio, uuid
from datetime import datetime
from .incident import Incident
import time
from soar.response.orchestrator import ResponseOrchestrator
from soar.analysis.incident_analyzer import IncidentAnalyzer
from soar.prediction.threat_predictor import ThreatPredictor
from soar.metrics.metrics import INCIDENTS_TOTAL, INCIDENT_LATENCY
from soar.utils.logging import get_logger

class ThreatDetectorIFace:
    def classify(self, event: dict): ...
class IncidentAnalyzerIFace:
    async def deep_analysis(self, incident: Incident): ...
class AutomatedResponderIFace:
    async def execute_playbook(self, incident: Incident): ...
class ThreatPredictorIFace:
    async def forecast_related_threats(self, incident: Incident): ...

class IncidentHandler:
    def __init__(self):
        self.detector = ThreatDetectorIFace()
        self.analyzer = IncidentAnalyzerIFace()
        self.responder = AutomatedResponderIFace()
        self.predictor = ThreatPredictorIFace()
        self.orchestrator = ResponseOrchestrator()
        self.analyzer = IncidentAnalyzer()
        self.predictor = ThreatPredictor()

    async def handle_incident(self, incident: dict) -> dict:
        start = time.time()
        get_logger.info(f"[Handler] Recebido incidente {incident}")

        async with asyncio.TaskGroup() as tg:
            tg.create_task(self.orchestrator.respond(incident))
            tg.create_task(asyncio.to_thread(self.analyzer.analyze, incident))
            tg.create_task(asyncio.to_thread(self.predictor.predict_related, incident))

        INCIDENTS_TOTAL.labels(type=incident.get("type")).inc()
        INCIDENT_LATENCY.observe(time.time() - start)

        return {"status": "completed", "incident": incident}
