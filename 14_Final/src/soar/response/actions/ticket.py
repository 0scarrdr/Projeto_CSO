from soar.integrations.ticket import create_servicenow_ticket, create_jira_ticket

def create_ticket_action(incident, system: str = "servicenow", summary: str = None, description: str = None):
    summary = summary or f"Incidente {incident.get('id')}"
    description = description or str(incident)
    if system == "servicenow":
        return create_servicenow_ticket(summary, description)
    elif system == "jira":
        return create_jira_ticket(summary, description)
    else:
        return {"error": "Sistema de ticket não suportado"}
