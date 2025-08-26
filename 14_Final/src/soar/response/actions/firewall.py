import requests
from ...utils.config import get_config
from ...utils.logging import get_logger
log = get_logger(__name__)

AZURE_FIREWALL_API_URL = "https://management.azure.com/subscriptions/<subscription_id>/resourceGroups/<resource_group>/providers/Microsoft.Network/azureFirewalls/<firewall_name>/blockIP?api-version=2022-05-01"
AZURE_TOKEN = "<access_token>" # Substitua pelo seu token

def block_ip(incident, ip: str):
    cfg = get_config()
    if cfg["dry_run"]:
        log.warning(f"[dry-run] Would block {ip} via Azure Firewall")
        return {"dry_run": True, "ip": ip}
    try:
        headers = {
            "Authorization": f"Bearer {AZURE_TOKEN}",
            "Content-Type": "application/json"
        }
        payload = {"ip": ip}
        response = requests.post(AZURE_FIREWALL_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        log.info(f"IP {ip} bloqueado via Azure Firewall")
        return {"ok": True, "ip": ip}
    except Exception as e:
        log.error(f"Erro ao bloquear IP no Azure Firewall: {e}")
        return {"ok": False, "error": str(e), "ip": ip}
