import os
def get_config():
    return {
        "dry_run": os.getenv("DRY_RUN","true").lower()=="true",
        "siem_outbox": os.getenv("SIEM_OUTBOX",".outbox/siem_events.jsonl"),
    }
