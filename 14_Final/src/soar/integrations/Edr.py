
import requests
import os
from dotenv import load_dotenv
from soar.utils.logging import logger


class DefenderEDRClient:
    def __init__(self):
        load_dotenv()
        self.api_url = os.getenv("DEFENDER_API_URL", "https://api.security.microsoft.com")
        self.api_key = os.getenv("DEFENDER_API_TOKEN")

    def execute_response(self, incident):
        host_id = incident.get("host_id")
        action = incident.get("action")
        if not host_id or not action:
            logger.error("[DefenderEDR] Incident missing host_id or action for response.")
            return {"error": "Missing host_id or action"}
        if action == "isolate":
            return self.isolate_host(host_id)
        elif action == "quarantine":
            return self.rollback_host(host_id)
        else:
            logger.error(f"[DefenderEDR] Unknown action: {action}")
            return {"error": f"Unknown action: {action}"}

    def isolate_host(self, host_id):
        url = f"{self.api_url}/api/machines/{host_id}/isolate"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            logger.info(f"[DefenderEDR] Host {host_id} isolated via Defender API.")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[DefenderEDR] Failed to isolate host: {e}")
            return {"error": str(e)}

    def rollback_host(self, host_id):
        url = f"{self.api_url}/api/machines/{host_id}/unisolate"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            logger.info(f"[DefenderEDR] Host {host_id} removed from isolation via Defender API.")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[DefenderEDR] Failed to unisolate host: {e}")
            return {"error": str(e)}

    def fetch_alerts(self):
        url = f"{self.api_url}/api/alerts"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            alerts = response.json()
            logger.info(f"[DefenderEDR] Fetched {len(alerts.get('value', []))} alerts from Defender API.")
            return alerts.get('value', [])
        except requests.RequestException as e:
            logger.error(f"[DefenderEDR] Failed to fetch alerts: {e}")
            return []