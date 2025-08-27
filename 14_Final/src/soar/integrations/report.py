import os
from datetime import datetime
from soar.utils.logging import get_logger

logger = get_logger(__name__)
REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../reports"))
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_incident_report(incident, results):
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_name = f"incident_{incident.get('id', 'unknown')}_{timestamp}.md"
    report_path = os.path.join(REPORTS_DIR, report_name)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Relatório de Incidente\n\n")
        f.write(f"**ID:** {incident.get('id', 'N/A')}\n\n")
        f.write(f"**Timestamp:** {timestamp}\n\n")
        f.write(f"**Dados:**\n\n{incident}\n\n")
        f.write(f"**Resultados:**\n\n{results}\n\n")
    logger.info(f"Relatório gerado: {report_path}")
    return {"status": "generated", "file": report_path}
