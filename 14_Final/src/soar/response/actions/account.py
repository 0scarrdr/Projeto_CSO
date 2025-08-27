from soar.integrations.account import suspend_account

def suspend_user_account(incident, user_id: str):
    return suspend_account(user_id)
