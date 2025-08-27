
import asyncio, uuid
import traceback
from datetime import datetime
from .incident import Incident
import time
from soar.integrations.siem import send_event
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
    async def execute_playbook(self, incident: dict):
        # Integração com EDR, Cloud e Backup conforme tipo de incidente
        from soar.integrations.Edr import EDRClient
        from soar.integrations.Cloud import CloudProvider, CloudManager
        from soar.integrations.Backup import BackupSystem
        edr = EDRClient(api_url="http://edr.local/api", api_key="changeme")
        cloud = CloudProvider()
        backup = BackupSystem(api_url="https://management.azure.com", token="<YOUR_AZURE_TOKEN>")
        # Exemplo: acionar resposta conforme tipo
        if incident.get("action") == "isolate":
            result = edr.execute_response(incident)
            return {"edr_response": result}
        elif incident.get("action") == "rollback_vm":
            vm_id = incident.get("vm_id")
            result = cloud.rollback_vm(vm_id)
            return {"cloud_vm_rollback": result}
        elif incident.get("action") == "restore_service":
            service_id = incident.get("service_id")
            cloud_mgr = CloudManager(api_url="https://management.azure.com", token="<YOUR_AZURE_TOKEN>")
            result = cloud_mgr.restore_service(service_id)
            return {"cloud_service_restore": result}
        elif incident.get("action") == "restore_backup":
            host = incident.get("host")
            result = backup.restore_backup(host, backup_id=None)
            return {"backup_restore": result}
        return {"response": "No action triggered"}
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

        # Enriquecimento CTI automático
        from soar.integrations.cti import CTIClient
        abuseipdb_api_key = "<YOUR_ABUSEIPDB_API_KEY>"  # Substitua pela sua chave
        cti = CTIClient(abuseipdb_api_key=abuseipdb_api_key)
        ip_to_check = incident.get("src_ip") or incident.get("dst_ip")
        cti_result = None
        if ip_to_check:
            cti_result = cti.check_ip(ip_to_check)
            incident["cti"] = cti_result

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

        send_event(incident)

        # Para métricas
        incident_type = incident.get("type") if isinstance(incident, dict) else getattr(incident, "type", None)
        INCIDENTS_TOTAL.labels(type=incident_type).inc()
        INCIDENT_LATENCY.observe(time.time() - start)

        if errors:
            return {"status": "error", "incident": incident, "errors": errors}
        # Devolver resultados agregados
        return {
            "status": "completed",
            "incident": incident,
            "cti": cti_result,
            "results": self.compile_results(response_result, analysis_result, prediction_result)
        }
