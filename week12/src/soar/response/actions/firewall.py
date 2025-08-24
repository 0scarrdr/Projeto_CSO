import subprocess
from ...utils.config import get_config
from ...utils.logging import get_logger
log = get_logger(__name__)

def block_ip(incident, ip: str):
    cfg = get_config()
    if cfg["dry_run"]:
        log.warning(f"[dry-run] Would block {ip} via iptables")
        return {"dry_run": True, "ip": ip}
    try:
        subprocess.run(["iptables","-A","INPUT","-s",ip,"-j","DROP"], check=True)
        return {"ok": True, "ip": ip}
    except Exception as e:
        log.exception("iptables failed")
        return {"ok": False, "error": str(e), "ip": ip}
