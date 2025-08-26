import json
import hashlib
from pathlib import Path
from datetime import datetime

# Definições de caminhos
LEDGER = Path(".evidence/ledger.jsonl")
STORE = Path(".evidence/store")

def _sha256(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

class EvidenceStore:
    def __init__(self):
        STORE.mkdir(parents=True, exist_ok=True)
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        if not LEDGER.exists():
            LEDGER.write_text("")

    def preserve(self, incident) -> str:
        # Extrair dados de forma robusta
        if isinstance(incident, dict):
            incident_id = incident.get("id")
            incident_type = incident.get("type")
            attributes = incident.get("attributes", incident)
        else:
            incident_id = getattr(incident, "id", None)
            incident_type = getattr(incident, "type", None)
            attributes = getattr(incident, "attributes", incident.__dict__)
        data = {
            "incident_id": incident_id,
            "type": incident_type,
            "attributes": attributes,
            "ts": datetime.utcnow().isoformat() + "Z"
        }
        # Garantir que o nome do ficheiro é válido
        file_id = incident_id if incident_id is not None else "unknown"
        b = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        digest = _sha256(b)
        f = STORE / f"{file_id}.json"
        f.write_bytes(b)
        with LEDGER.open("a", encoding="utf-8") as L:
            L.write(json.dumps({"artifact": str(f), "sha256": digest}) + "\n")
        return str(f)

# Exportar a classe para ser usada em outros módulos
EvidenceStore = EvidenceStore