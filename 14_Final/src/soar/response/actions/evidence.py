from soar.integrations.evidence import preserve_evidence

def preserve_incident_evidence(incident, file_path: str):
    incident_id = incident.get("id") if isinstance(incident, dict) else getattr(incident, "id", None)
    return preserve_evidence(file_path, incident_id)
