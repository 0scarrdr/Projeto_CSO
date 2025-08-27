"""
CTI (Cyber Threat Intelligence) integration module.
Stub version: checks IPs/domains against a local blacklist (JSON file).
Can be extended to call external feeds (MISP, OTX, etc.).
"""

import json
import os
from pathlib import Path
from soar.utils.logging import get_logger

logger = get_logger(__name__)

DATA_DIR = Path(__file__).parent.parent.parent / "data"
CTI_FILE = DATA_DIR / "cti_blacklist.json"


class CTIClient:
    def __init__(self, source: str = None, abuseipdb_api_key: str = None):
        from dotenv import load_dotenv
        import os
        load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../../../.env'))
        self.source = source or str(CTI_FILE)
        self.indicators = self._load_indicators()
        self.abuseipdb_api_key = abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY")

    def _load_indicators(self):
        if os.path.exists(self.source):
            try:
                with open(self.source, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Erro a carregar CTI de {self.source}: {e}")
        # fallback: lista simples
        return {"ips": ["10.0.0.66", "192.168.1.250"], "domains": ["evil.com"]}

    def check_ip(self, ip: str) -> dict:
        # Primeiro verifica local
        if ip in self.indicators.get("ips", []):
            return {"malicious": True, "confidence": 0.9, "source": "local"}
        # Se tiver API AbuseIPDB, consulta online
        if self.abuseipdb_api_key:
            import requests
            headers = {
                "Key": self.abuseipdb_api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }
            try:
                response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                response.raise_for_status()
                data = response.json()
                score = data.get("data", {}).get("abuseConfidenceScore", 0)
                return {"malicious": score > 50, "confidence": score/100, "source": "AbuseIPDB", "details": data}
            except Exception as e:
                return {"malicious": False, "error": str(e)}
        return {"malicious": False}

    def check_domain(self, domain: str) -> dict:
        if domain in self.indicators.get("domains", []):
            return {"malicious": True, "confidence": 0.85, "source": "local"}
        return {"malicious": False}
