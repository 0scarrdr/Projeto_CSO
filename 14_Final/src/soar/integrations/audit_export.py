import os
import json
from datetime import datetime
from soar.utils.logging import get_logger

logger = get_logger(__name__)
EVIDENCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../evidence"))
AUDIT_LOG = os.path.join(EVIDENCE_DIR, "audit_log.json")
EXPORT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../exports"))
os.makedirs(EXPORT_DIR, exist_ok=True)

def export_audit_log_html():
    if not os.path.exists(AUDIT_LOG):
        logger.error("Audit log não encontrado.")
        return {"status": "error", "msg": "Audit log não encontrado."}
    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        audit_data = json.load(f)
    html = ["<html><head><title>Cadeia de Custódia</title></head><body>", "<h1>Cadeia de Custódia de Evidências</h1>", "<table border='1'><tr><th>Incidente</th><th>Usuário</th><th>Timestamp</th><th>Arquivo</th><th>Hash</th></tr>"]
    for entry in audit_data:
        html.append(f"<tr><td>{entry.get('incident_id')}</td><td>{entry.get('user')}</td><td>{entry.get('timestamp')}</td><td>{entry.get('file')}</td><td>{entry.get('hash')}</td></tr>")
    html.append("</table></body></html>")
    export_path = os.path.join(EXPORT_DIR, f"audit_log_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html")
    with open(export_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    logger.info(f"Audit log exportado para {export_path}")
    return {"status": "exported", "file": export_path}
