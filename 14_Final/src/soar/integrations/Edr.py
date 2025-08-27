import requests
from soar.utils.logging import logger

class EDRClient:
    def execute_response(self, incident):
        host_id = incident.get("host_id")
        action = incident.get("action")
        if not host_id or not action:
            logger.error("[EDR] Incident missing host_id or action for response.")
            return {"error": "Missing host_id or action"}
        if action == "isolate":
            return self.isolate_host(host_id)
        elif action == "quarantine":
            return self.rollback_host(host_id)
        else:
            logger.error(f"[EDR] Unknown action: {action}")
            return {"error": f"Unknown action: {action}"}
    def rollback_host(self, host_id):
        url = f"{self.api_url}/hosts/{host_id}/isolate"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            logger.info(f"[EDR] Host {host_id} isolated/quarantined via API.")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[EDR] Failed to isolate/quarantine host: {e}")
            return {"error": str(e)}
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.api_key = api_key

    def isolate_host(self, host_id):
        url = f"{self.api_url}/hosts/{host_id}/isolate"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            logger.info(f"[EDR] Host {host_id} isolated via API.")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[EDR] Failed to isolate host: {e}")
            return {"error": str(e)}

    def fetch_alerts(self):
        url = f"{self.api_url}/alerts"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            alerts = response.json()
            logger.info(f"[EDR] Fetched {len(alerts)} alerts from API.")
            return alerts
        except requests.RequestException as e:
            logger.error(f"[EDR] Failed to fetch alerts: {e}")
            return []