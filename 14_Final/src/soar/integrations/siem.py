import os, json
from ..utils.config import get_config
from ..utils.logging import get_logger
log = get_logger(__name__)

import json
import requests
from soar.utils.logging import get_logger

logger = get_logger(__name__)

SIEM_API_URL = "https://<workspace-id>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
SIEM_API_KEY = "<primary-key>" # Substitua pelo seu valor

def send_event(event):
    headers = {
        "Content-Type": "application/json",
        "Log-Type": "SOAREvents",
        "x-api-key": SIEM_API_KEY
    }
    try:
        response = requests.post(SIEM_API_URL, headers=headers, data=json.dumps(event))
        response.raise_for_status()
        logger.info(f"Evento enviado para Azure Sentinel: {event}")
        return {"sent": True, "event": event}
    except Exception as e:
        logger.error(f"Erro ao enviar evento para SIEM: {e}")
        return {"sent": False, "error": str(e), "event": event}
    
    path = get_config()["siem_outbox"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path,"a",encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
    log.info(f"SIEM outbox <- event {event.get('incident_id','?')}")
    return True
    path = get_config()["siem_outbox"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path,"a",encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")
    log.info(f"SIEM outbox <- event {payload.get('incident_id','?')}")
    return True
