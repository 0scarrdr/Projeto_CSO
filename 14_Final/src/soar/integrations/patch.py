"""
Patch Management integration: aplica patches/configuração via Azure Automation.
"""
import requests
from dotenv import load_dotenv
import os
from soar.utils.logging import get_logger

logger = get_logger(__name__)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../../../.env'))
AZURE_AUTOMATION_API_URL = os.getenv("AZURE_AUTOMATION_API_URL")
AZURE_TOKEN = os.getenv("AZURE_TOKEN")

def apply_patch(runbook_name, parameters=None):
    url = AZURE_AUTOMATION_API_URL.replace("<runbook_name>", runbook_name)
    headers = {
        "Authorization": f"Bearer {AZURE_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"parameters": parameters or {}}
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        logger.info(f"Patch/configuração aplicada via Azure Automation: {runbook_name}")
        return {"status": "patched", "runbook": runbook_name}
    except Exception as e:
        logger.error(f"Erro ao aplicar patch/configuração: {e}")
        return {"status": "error", "runbook": runbook_name, "error": str(e)}
