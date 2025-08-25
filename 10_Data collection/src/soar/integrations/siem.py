import os, json
from ..utils.config import get_config
from ..utils.logging import get_logger
log = get_logger(__name__)

def send_event(payload: dict):
    path = get_config()["siem_outbox"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path,"a",encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")
    log.info(f"SIEM outbox <- event {payload.get('incident_id','?')}")
    return True
