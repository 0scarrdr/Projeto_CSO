import requests
from soar.utils.logging import logger

class CloudManager:
    def __init__(self, api_url, token):
        self.api_url = api_url
        self.token = token

    def block_account(self, account_id):
        url = f"{self.api_url}/accounts/{account_id}/block"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            logger.info(f"[Cloud] Account {account_id} blocked via API.")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[Cloud] Failed to block account: {e}")
            return {"error": str(e)}

    def restore_service(self, service_id):
        url = f"{self.api_url}/services/{service_id}/restore"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            logger.info(f"[Cloud] Service {service_id} restored via API.")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[Cloud] Failed to restore service: {e}")
            return {"error": str(e)}