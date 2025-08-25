from ...integrations.siem import send_event
def siem(incident, level: str="info"):
    return {"sent": send_event({
        "incident_id": incident.id,
        "type": incident.type,
        "severity": incident.severity,
        "level": level,
        "attributes": incident.attributes
    })}
