import os
import shutil
import hashlib
import json
from datetime import datetime
from dotenv import load_dotenv
from soar.utils.logging import get_logger

logger = get_logger(__name__)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../../../.env'))
EVIDENCE_DIR = os.getenv("EVIDENCE_DIR") or os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../evidence"))
AUDIT_LOG = os.path.join(EVIDENCE_DIR, "audit_log.json")

os.makedirs(EVIDENCE_DIR, exist_ok=True)

def preserve_evidence(file_path, incident_id=None, user=None):
    try:
        if not os.path.exists(file_path):
            logger.error(f"Arquivo de evidência não encontrado: {file_path}")
            return {"status": "error", "file": file_path}
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.basename(file_path)
        dest_name = f"{incident_id or 'incident'}_{timestamp}_{base_name}"
        dest_path = os.path.join(EVIDENCE_DIR, dest_name)
        shutil.copy2(file_path, dest_path)
        # Calcular hash da evidência
        with open(dest_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        # Registrar trilha de auditoria
        audit_entry = {
            "incident_id": incident_id,
            "user": user or "system",
            "timestamp": timestamp,
            "file": dest_path,
            "hash": file_hash
        }
        try:
            if os.path.exists(AUDIT_LOG):
                with open(AUDIT_LOG, "r", encoding="utf-8") as f:
                    audit_data = json.load(f)
            else:
                audit_data = []
        except Exception:
            audit_data = []
        audit_data.append(audit_entry)
        with open(AUDIT_LOG, "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2)
        logger.info(f"Evidência preservada: {dest_path} | Hash: {file_hash}")
        return {"status": "preserved", "file": dest_path, "hash": file_hash}
    except Exception as e:
        logger.error(f"Erro ao preservar evidência: {e}")
        return {"status": "error", "file": file_path, "error": str(e)}
