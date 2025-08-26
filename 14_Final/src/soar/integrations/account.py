"""
Account Management integration: suspende contas de utilizador via Azure AD.
"""
import requests
from soar.utils.logging import get_logger

logger = get_logger(__name__)
AZURE_AD_API_URL = "https://graph.microsoft.com/v1.0/users/{user_id}/blockSignIn"
AZURE_TOKEN = "<access_token>" # Substitua pelo seu token

def suspend_account(user_id):
    url = AZURE_AD_API_URL.format(user_id=user_id)
    headers = {
        "Authorization": f"Bearer {AZURE_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"accountEnabled": False}
    try:
        response = requests.patch(url, headers=headers, json=payload)
        response.raise_for_status()
        logger.info(f"Conta {user_id} suspensa via Azure AD")
        return {"status": "suspended", "user_id": user_id}
    except Exception as e:
        logger.error(f"Erro ao suspender conta no Azure AD: {e}")
        return {"status": "error", "user_id": user_id, "error": str(e)}
