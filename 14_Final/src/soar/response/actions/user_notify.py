from soar.integrations.notify import notify_user

def notify_user_action(incident, user_id: str, subject: str = None, body: str = None):
    subject = subject or f"Alerta de Segurança: Incidente {incident.get('id')}"
    body = body or f"Um incidente foi detectado: {incident}"
    return notify_user(user_id, subject, body)
