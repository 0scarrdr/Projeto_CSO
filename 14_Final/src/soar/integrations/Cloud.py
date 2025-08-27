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
        import requests
        from dotenv import load_dotenv
        import os

        load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../../../.env'))
        AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
        AZURE_RESOURCE_GROUP = os.getenv("AZURE_RESOURCE_GROUP")
        AZURE_TOKEN = os.getenv("AZURE_TOKEN")
        AZURE_API_BASE = os.getenv("AZURE_API_BASE")

        class AzureCloudManager:
            def __init__(self, token=AZURE_TOKEN, subscription_id=AZURE_SUBSCRIPTION_ID, resource_group=AZURE_RESOURCE_GROUP):
                self.token = token
                self.subscription_id = subscription_id
                self.resource_group = resource_group
                self.headers = {
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json"
                }

            def list_vms(self):
                url = f"{AZURE_API_BASE}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Compute/virtualMachines?api-version=2022-08-01"
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                return response.json()

            def start_vm(self, vm_name):
                url = f"{AZURE_API_BASE}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/start?api-version=2022-08-01"
                response = requests.post(url, headers=self.headers)
                response.raise_for_status()
                return response.status_code == 202

            def stop_vm(self, vm_name):
                url = f"{AZURE_API_BASE}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/powerOff?api-version=2022-08-01"
                response = requests.post(url, headers=self.headers)
                response.raise_for_status()
                return response.status_code == 202

            def get_vm_status(self, vm_name):
                url = f"{AZURE_API_BASE}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/instanceView?api-version=2022-08-01"
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                return response.json()