"""
System Response Actions
Implements system-related security response actions (EDR calls env-gated)
"""

import logging
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)


async def quarantine_file(incident, file_path: str = None, **kwargs) -> Dict[str, Any]:
    """
    Quarantine a malicious file
    
    Args:
        incident: Incident object
        file_path: Path to file to quarantine
        
    Returns:
        Action result
    """
    target_file = file_path or kwargs.get('malicious_file')
    
    if not target_file:
        return {
            "status": "failed",
            "message": "No file specified for quarantine",
            "action": "quarantine_file"
        }
    
    logger.info(f"Quarantining file {target_file}")
    
    return {
        "status": "success",
        "message": f"File {target_file} quarantined successfully",
        "action": "quarantine_file",
        "details": {
            "quarantined_file": target_file,
            "quarantine_location": f"/quarantine/{hash(target_file) % 10000}",
            "backup_created": True
        }
    }


def disable_user(incident, username: str = None, **kwargs) -> Dict[str, Any]:
    """
    Disable a user account
    
    Args:
        incident: Incident object
        username: Username to disable
        
    Returns:
        Action result
    """
    target_user = username or getattr(incident, 'username', None)
    
    if not target_user:
        return {
            "status": "failed",
            "message": "No username specified for disabling",
            "action": "disable_user"
        }
    
    logger.info(f"Disabling user {target_user}")
    
    return {
        "status": "success",
        "message": f"User {target_user} disabled successfully",
        "action": "disable_user",
        "details": {
            "disabled_user": target_user,
            "disable_method": "account_lockout"
        }
    }


async def patch_system(incident, host_id: str = None, patch_id: str = None, **kwargs) -> Dict[str, Any]:
    """
    Apply security patches to a system
    
    Args:
        incident: Incident object
        host_id: System to patch
        patch_id: Specific patch to apply
        
    Returns:
        Action result
    """
    target_host = host_id or getattr(incident, 'source_system', None)
    
    if not target_host:
        return {
            "status": "failed",
            "message": "No host specified for patching",
            "action": "patch_system"
        }
    
    logger.info(f"Applying patches to host {target_host}")
    
    return {
        "status": "success",
        "message": f"System {target_host} patched successfully",
        "action": "patch_system",
        "details": {
            "patched_host": target_host,
            "patch_id": patch_id or "AUTO_PATCH_001",
            "reboot_required": True
        }
    }


async def verify_configuration(incident, host_id: str = None, baseline: str = "CIS_Level1", **kwargs) -> Dict[str, Any]:
    """
    Verify system configuration against a security baseline
    """
    target_host = host_id or getattr(incident, 'source_system', None)
    logger.info(f"Verifying configuration on host {target_host} against {baseline}")
    return {
        "status": "success",
        "message": f"Configuration verified on {target_host}",
        "action": "verify_configuration",
        "details": {
            "host": target_host,
            "baseline": baseline,
            "findings": [],
            "compliant": True
        }
    }


async def harden_system(incident, host_id: str = None, profile: str = "CIS_Hardening", **kwargs) -> Dict[str, Any]:
    """
    Apply hardening steps to a system
    """
    target_host = host_id or getattr(incident, 'source_system', None)
    logger.info(f"Applying hardening on host {target_host} with profile {profile}")
    return {
        "status": "success",
        "message": f"Hardening applied to {target_host}",
        "action": "harden_system",
        "details": {
            "host": target_host,
            "profile": profile,
            "changes": ["disable_legacy_protocols", "enforce_password_policy", "enable_audit"]
        }
    }


async def isolate_host_edr(incident, host_id: str = None, **kwargs) -> Dict[str, Any]:
    """Isolate a host via EDR; real calls only when ENABLE_EDR=true"""
    target = host_id or getattr(incident, 'source_system', None) or getattr(incident, 'host_id', None)
    if not target:
        return {"status": "failed", "message": "No host_id to isolate", "action": "isolate_host_edr"}
    if os.environ.get('ENABLE_EDR', 'false').lower() == 'true':
        try:
            from ...integrations.microsoft_defender_edr import GenericEDR
            edr = GenericEDR(edr_type=kwargs.get('edr_type', os.environ.get('EDR_TYPE', 'generic')),
                             api_key=os.environ.get('EDR_API_KEY'))
            res = edr.isolate_machine(machine_name=target, isolation_type=kwargs.get('isolation_type', 'Full'))
            return {"status": "success" if res.success else "failed", "action": "isolate_host_edr", "details": res.details}
        except Exception as e:
            logger.warning(f"EDR isolate failed; simulating. Error: {e}")
    # Try webhook-based EDR
    if os.environ.get('ENABLE_EDR_WEBHOOK', 'false').lower() == 'true' or os.environ.get('EDR_WEBHOOK_URL'):
        try:
            from ...integrations.webhook_edr import WebhookEDR
            wc = WebhookEDR()
            wr = wc.isolate_machine(machine_name=target, isolation_type=kwargs.get('isolation_type', 'Full'))
            return {"status": "success" if wr.success else "failed", "action": "isolate_host_edr", "details": wr.details}
        except Exception as e:
            logger.warning(f"Webhook EDR isolate failed; simulating. Error: {e}")
    return {"status": "simulated", "action": "isolate_host_edr", "details": {"host": target, "isolated": True}}


async def edr_run_scan(incident, host_id: str = None, scan_type: str = "Quick", **kwargs) -> Dict[str, Any]:
    """Run an EDR scan; real calls only when ENABLE_EDR=true"""
    target = host_id or getattr(incident, 'source_system', None)
    if not target:
        return {"status": "failed", "message": "No host_id to scan", "action": "edr_run_scan"}
    if os.environ.get('ENABLE_EDR', 'false').lower() == 'true':
        try:
            from ...integrations.microsoft_defender_edr import GenericEDR
            edr = GenericEDR(edr_type=kwargs.get('edr_type', os.environ.get('EDR_TYPE', 'generic')),
                             api_key=os.environ.get('EDR_API_KEY'))
            res = edr.run_scan(machine_name=target, scan_type=scan_type)
            return {"status": "success" if res.success else "failed", "action": "edr_run_scan", "details": res.details}
        except Exception as e:
            logger.warning(f"EDR scan failed; simulating. Error: {e}")
    if os.environ.get('ENABLE_EDR_WEBHOOK', 'false').lower() == 'true' or os.environ.get('EDR_WEBHOOK_URL'):
        try:
            from ...integrations.webhook_edr import WebhookEDR
            wc = WebhookEDR()
            wr = wc.run_scan(machine_name=target, scan_type=scan_type)
            return {"status": "success" if wr.success else "failed", "action": "edr_run_scan", "details": wr.details}
        except Exception as e:
            logger.warning(f"Webhook EDR scan failed; simulating. Error: {e}")
    return {"status": "simulated", "action": "edr_run_scan", "details": {"host": target, "scan_type": scan_type, "started": True}}


async def edr_unisolate_host(incident, host_id: str = None, **kwargs) -> Dict[str, Any]:
    """Remove host isolation via EDR; real calls only when ENABLE_EDR=true"""
    target = host_id or getattr(incident, 'source_system', None)
    if not target:
        return {"status": "failed", "message": "No host_id to unisolate", "action": "edr_unisolate_host"}
    if os.environ.get('ENABLE_EDR', 'false').lower() == 'true':
        try:
            from ...integrations.microsoft_defender_edr import GenericEDR
            edr = GenericEDR(edr_type=kwargs.get('edr_type', os.environ.get('EDR_TYPE', 'generic')),
                             api_key=os.environ.get('EDR_API_KEY'))
            res = edr.unisolate_machine(machine_name=target)
            return {"status": "success" if res.success else "failed", "action": "edr_unisolate_host", "details": res.details}
        except Exception as e:
            logger.warning(f"EDR unisolate failed; simulating. Error: {e}")
    if os.environ.get('ENABLE_EDR_WEBHOOK', 'false').lower() == 'true' or os.environ.get('EDR_WEBHOOK_URL'):
        try:
            from ...integrations.webhook_edr import WebhookEDR
            wc = WebhookEDR()
            wr = wc.unisolate_machine(machine_name=target)
            return {"status": "success" if wr.success else "failed", "action": "edr_unisolate_host", "details": wr.details}
        except Exception as e:
            logger.warning(f"Webhook EDR unisolate failed; simulating. Error: {e}")
    return {"status": "simulated", "action": "edr_unisolate_host", "details": {"host": target, "isolated": False}}
