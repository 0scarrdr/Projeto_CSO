
import asyncio, uuid
import traceback
from datetime import datetime
from .incident import Incident
import time
from soar.response.orchestrator import ResponseOrchestrator
from soar.analysis.incident_analyzer import IncidentAnalyzer
from soar.prediction.threat_predictor import ThreatPredictor
from soar.metrics.metrics import INCIDENTS_TOTAL, INCIDENT_LATENCY
from soar.utils.logging import get_logger

class IncidentObject:
    def __init__(self, data):
        if isinstance(data, dict):
            for k, v in data.items():
                setattr(self, k, v)
            self.attributes = data
        else:
            # Assume que já é objeto
            for k in dir(data):
                if not k.startswith("_"):
                    setattr(self, k, getattr(data, k))
            self.attributes = data.__dict__

class ThreatDetectorIFace:
    def classify(self, event: dict): ...
class IncidentAnalyzerIFace:
    async def deep_analysis(self, incident: Incident): ...
class AutomatedResponderIFace:
    async def execute_playbook(self, incident: Incident): ...
class ThreatPredictorIFace:
    async def forecast_related_threats(self, incident: Incident): ...

class IncidentHandler:
    def compile_results(self, response_result, analysis_result, prediction_result):
        return {
            "response": response_result,
            "analysis": analysis_result,
            "prediction": prediction_result
        }
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
        logger = get_logger("handler")
        logger.info(f"[Handler] Recebido incidente {incident}")

        # Robustez: garantir que o incidente é sempre objeto com atributos
        incident_obj = IncidentObject(incident)

        errors = []
        response_result = analysis_result = prediction_result = None
        try:
            async with asyncio.TaskGroup() as tg:
                response_task = tg.create_task(self.orchestrator.execute({}, incident_obj))
                analysis_task = tg.create_task(asyncio.to_thread(self.analyzer.analyze, incident))
                prediction_task = tg.create_task(asyncio.to_thread(self.predictor.predict_related, incident))
            response_result = response_task.result()
            analysis_result = analysis_task.result()
            prediction_result = prediction_task.result()
        except Exception as exc:
            tb = traceback.format_exc()
            logger.error(f"Erro em TaskGroup: {exc}\nTraceback:\n{tb}")
            errors.append(f"{exc}\nTraceback:\n{tb}")

        # Para métricas, garantir que é dicionário
        incident_type = incident.get("type") if isinstance(incident, dict) else getattr(incident, "type", None)
        INCIDENTS_TOTAL.labels(type=incident_type).inc()
        INCIDENT_LATENCY.observe(time.time() - start)

        if errors:
            return {"status": "error", "incident": incident, "errors": errors}
        # Devolver resultados agregados
        return {
            "status": "completed",
            "incident": incident,
            "results": self.compile_results(response_result, analysis_result, prediction_result)
        }
