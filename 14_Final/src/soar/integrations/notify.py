"""
User Notification integration: envia alertas por email via Microsoft Graph API.
"""
import requests
from dotenv import load_dotenv
import os
from soar.utils.logging import get_logger

logger = get_logger(__name__)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../../../.env'))
GRAPH_API_URL = os.getenv("GRAPH_API_URL")
AZURE_TOKEN = os.getenv("AZURE_TOKEN")

def notify_user(user_id, subject, body):
    url = GRAPH_API_URL.format(user_id=user_id)
    headers = {
        "Authorization": f"Bearer {AZURE_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body},
            "toRecipients": [{"emailAddress": {"address": user_id}}]
        }
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        logger.info(f"Notificação enviada para {user_id}")
        return {"status": "notified", "user_id": user_id}
    except Exception as e:
        logger.error(f"Erro ao notificar utilizador: {e}")
        return {"status": "error", "user_id": user_id, "error": str(e)}
