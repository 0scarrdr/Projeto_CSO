import requests
from soar.utils.logging import logger

class BackupSystem:
    def __init__(self, api_url, token):
        self.api_url = api_url
        self.token = token

    def restore_backup(self, system_id, backup_id):
        url = f"{self.api_url}/systems/{system_id}/backups/{backup_id}/restore"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            logger.info(f"[Backup] Backup {backup_id} restored for system {system_id} via API.")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[Backup] Failed to restore backup: {e}")
            return {"error": str(e)}

    def verify_backup(self, backup_id):
        url = f"{self.api_url}/backups/{backup_id}/verify"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            logger.info(f"[Backup] Backup {backup_id} verified via API.")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"[Backup] Failed to verify backup: {e}")
            return {"error": str(e)}