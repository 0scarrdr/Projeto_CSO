
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
        elif incident.get("action") == "suspend_account":
            user_id = incident.get("user_id")
            from soar.integrations.account import suspend_account
            result = suspend_account(user_id)
            return {"account_suspension": result}
        elif incident.get("action") == "preserve_evidence":
            file_path = incident.get("evidence_path")
            from soar.integrations.evidence import preserve_evidence
            result = preserve_evidence(file_path, incident.get("id"))
            return {"evidence_preservation": result}
        elif incident.get("action") == "apply_patch":
            runbook = incident.get("runbook")
            parameters = incident.get("parameters")
            from soar.integrations.patch import apply_patch
            result = apply_patch(runbook_name=runbook, parameters=parameters)
            return {"patch_management": result}
        elif incident.get("action") == "notify_user":
            user_id = incident.get("user_id")
            subject = incident.get("subject")
            body = incident.get("body")
            from soar.integrations.notify import notify_user
            result = notify_user(user_id, subject or f"Alerta de Segurança: Incidente {incident.get('id')}", body or str(incident))
            return {"user_notification": result}
        elif incident.get("action") == "verify_config":
            file_path = incident.get("config_path")
            from soar.integrations.config_verify import verify_config
            result = verify_config(file_path)
            return {"config_verification": result}
        elif incident.get("action") == "restore_system":
            # Dispatcher: tenta restaurar via backup, cloud ou serviço
            from soar.integrations.Backup import BackupSystem
            from soar.integrations.Cloud import CloudProvider, CloudManager
            backup = BackupSystem(api_url="https://management.azure.com", token="<YOUR_AZURE_TOKEN>")
            cloud = CloudProvider()
            cloud_mgr = CloudManager(api_url="https://management.azure.com", token="<YOUR_AZURE_TOKEN>")
            host = incident.get("host")
            vm_id = incident.get("vm_id")
            service_id = incident.get("service_id")
            if host:
                result = backup.restore_backup(host, backup_id=None)
                return {"system_restoration": result}
            elif vm_id:
                result = cloud.rollback_vm(vm_id)
                return {"system_restoration": result}
            elif service_id:
                result = cloud_mgr.restore_service(service_id)
                return {"system_restoration": result}
            return {"system_restoration": "No restoration action triggered"}
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
                # Previsão ML
                from soar.analysis.threat_predictor_ml import ThreatPredictorML
                ml_predictor = ThreatPredictorML()
                features = [1 if incident.get('type') == 'malware' else 0, incident.get('severity', 1)]
                ml_prediction = ml_predictor.predict(features)
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
        # Gerar relatório automático
        from soar.integrations.report import generate_incident_report
        results = self.compile_results(response_result, analysis_result, prediction_result)
        report = generate_incident_report(incident, results)
        # Devolver resultados agregados
        return {
            "status": "completed",
            "incident": incident,
            "cti": cti_result,
            "results": results,
            "ml_prediction": ml_prediction,
            "report": report
        }
