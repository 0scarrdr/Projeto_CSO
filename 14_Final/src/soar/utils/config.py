import os

DRY_RUN_FIREWALL = os.getenv("DRY_RUN_FIREWALL", "true").lower() == "true"
DRY_RUN_ISOLATION = os.getenv("DRY_RUN_ISOLATION", "true").lower() == "true"
DRY_RUN_RECOVERY = os.getenv("DRY_RUN_RECOVERY", "true").lower() == "true"

def get_config():
    return {
        "dry_run": os.getenv("DRY_RUN","true").lower()=="true",
        "siem_outbox": os.getenv("SIEM_OUTBOX",".outbox/siem_events.jsonl"),
    }




