import os
from datetime import datetime
from soar.utils.logging import get_logger

logger = get_logger(__name__)
DOCS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../docs"))
os.makedirs(DOCS_DIR, exist_ok=True)

MODULES = [
    "core/handler.py",
    "integrations/siem.py",
    "integrations/firewall.py",
    "integrations/cloud.py",
    "integrations/backup.py",
    "integrations/account.py",
    "integrations/evidence.py",
    "integrations/patch.py",
    "integrations/cti.py",
    "integrations/report.py",
    "integrations/ticket.py",
    "integrations/config_verify.py",
    "analysis/threat_predictor_ml.py",
    "response/orchestrator.py",
]

PLAYBOOKS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src/soar/playbooks"))

def generate_docs():
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    doc_path = os.path.join(DOCS_DIR, f"SOAR_documentation_{timestamp}.md")
    with open(doc_path, "w", encoding="utf-8") as f:
        f.write(f"# SOAR Documentation\n\nGerado em {timestamp}\n\n")
        f.write("## Módulos Principais\n\n")
        for mod in MODULES:
            f.write(f"### {mod}\n\n")
            mod_path = os.path.abspath(os.path.join(DOCS_DIR, "../src/soar", mod))
            if os.path.exists(mod_path):
                with open(mod_path, "r", encoding="utf-8") as mf:
                    lines = mf.readlines()
                    doc_lines = [l for l in lines if l.strip().startswith('"""') or l.strip().startswith('#')]
                    f.writelines(doc_lines)
            f.write("\n\n")
        f.write("## Playbooks\n\n")
        if os.path.exists(PLAYBOOKS_DIR):
            for pb in os.listdir(PLAYBOOKS_DIR):
                if pb.endswith(".yml"):
                    f.write(f"### {pb}\n\n")
                    pb_path = os.path.join(PLAYBOOKS_DIR, pb)
                    with open(pb_path, "r", encoding="utf-8") as pbf:
                        f.writelines(pbf.readlines())
                    f.write("\n\n")
    logger.info(f"Documentação gerada: {doc_path}")
    return {"status": "generated", "file": doc_path}
