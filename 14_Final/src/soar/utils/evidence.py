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
        data = {
            "incident_id": incident.id,
            "type": incident.type,
            "attributes": incident.attributes,
            "ts": datetime.utcnow().isoformat() + "Z"
        }
        b = json.dumps(data, sort_keys=True).encode("utf-8")
        digest = _sha256(b)
        f = STORE / f"{incident.id}.json"
        f.write_bytes(b)
        with LEDGER.open("a", encoding="utf-8") as L:
            L.write(json.dumps({"artifact": str(f), "sha256": digest}) + "\n")
        return str(f)

# Exportar a classe para ser usada em outros módulos
EvidenceStore = EvidenceStore