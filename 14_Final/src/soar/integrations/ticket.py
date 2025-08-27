import requests
from dotenv import load_dotenv
import os
from soar.utils.logging import get_logger

logger = get_logger(__name__)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../../../.env'))
SERVICENOW_API_URL = os.getenv("SERVICENOW_API_URL")
SERVICENOW_USER = os.getenv("SERVICENOW_USER")
SERVICENOW_PASS = os.getenv("SERVICENOW_PASS")
JIRA_API_URL = os.getenv("JIRA_API_URL")
JIRA_USER = os.getenv("JIRA_USER")
JIRA_TOKEN = os.getenv("JIRA_TOKEN")

def create_servicenow_ticket(short_description, description):
    payload = {
        "short_description": short_description,
        "description": description
    }
    try:
        response = requests.post(
            SERVICENOW_API_URL,
            auth=(SERVICENOW_USER, SERVICENOW_PASS),
            json=payload
        )
        response.raise_for_status()
        logger.info("Ticket criado no ServiceNow")
        return response.json()
    except Exception as e:
        logger.error(f"Erro ao criar ticket ServiceNow: {e}")
        return {"error": str(e)}

def create_jira_ticket(summary, description, project_key="PROJ"):
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Task"}
        }
    }
    headers = {
        "Authorization": f"Basic {JIRA_USER}:{JIRA_TOKEN}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(
            JIRA_API_URL,
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        logger.info("Ticket criado no Jira")
        return response.json()
    except Exception as e:
        logger.error(f"Erro ao criar ticket Jira: {e}")
        return {"error": str(e)}
