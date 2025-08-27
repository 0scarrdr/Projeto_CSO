import requests

AZURE_SUBSCRIPTION_ID = "405650f3-310c-4f72-b8ea-81e0c5764c85"
AZURE_RESOURCE_GROUP = "ProjetoCSO"
AZURE_TOKEN = "<YOUR_AZURE_TOKEN>"  # Use o mesmo token do firewall ou obtenha um novo
AZURE_API_BASE = "https://management.azure.com"

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
