def isolate_host(incident, host_id: str|None=None):
    return {"dry_run": True, "host": host_id or incident.attributes.get("host_id","unknown")}
