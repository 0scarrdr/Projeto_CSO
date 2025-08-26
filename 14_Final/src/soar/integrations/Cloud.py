import requests
from soar.utils.logging import logger
from soar.utils.logging import get_logger
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient

logger = get_logger(__name__)

class CloudProvider:
    def __init__(self, subscription_id=None):
        self.credential = DefaultAzureCredential()
        self.subscription_id = subscription_id or "405650f3-310c-4f72-b8ea-81e0c5764c85
"
        self.client = ComputeManagementClient(self.credential, self.subscription_id)

    def rollback_vm(self, vm_id: str):
        # Exemplo: listar VMs e simular rollback
        vms = list(self.client.virtual_machines.list_all())
        for vm in vms:
            if vm.name == vm_id:
                # Aqui pode chamar snapshot/restore real
                logger.info(f"Rollback VM {vm_id}")
                return {"status": "rolled_back", "vm_id": vm_id}
        return {"status": "not_found", "vm_id": vm_id}

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