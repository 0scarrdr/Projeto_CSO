import requests
from soar.utils.logging import logger

class BackupSystem:
    def restore_backup_azure(self, vm_name):
        AZURE_BACKUP_API_URL = "https://management.azure.com/subscriptions/<subscription_id>/resourceGroups/<resource_group>/providers/Microsoft.RecoveryServices/vaults/<vault_name>/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;<vm_name>/protectedItems/VM;iaasvmcontainerv2;<vm_name>/restore?api-version=2021-01-01"
        AZURE_TOKEN = "<access_token>" # Substitua pelo seu token
        try:
            headers = {
                "Authorization": f"Bearer {AZURE_TOKEN}",
                "Content-Type": "application/json"
            }
            payload = {"vmName": vm_name}
            url = AZURE_BACKUP_API_URL.replace("<vm_name>", vm_name)
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            logger.info(f"Backup restaurado para {vm_name} via Azure Backup")
            return {"status": "restored", "host": vm_name}
        except Exception as e:
            logger.error(f"Erro ao restaurar backup no Azure: {e}")
            return {"status": "error", "host": vm_name, "error": str(e)}
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