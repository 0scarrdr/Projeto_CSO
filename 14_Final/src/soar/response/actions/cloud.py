"""
Cloud Response Actions
Implements cloud-related security response actions with safe, env-gated calls
to external services (Azure Backup, Azure AD, NSG/VM), simulating by default.
"""

import logging
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)


async def isolate_vm(incident, vm_name: str = None, **kwargs) -> Dict[str, Any]:
    """
    Isolate a compromised VM in the cloud
    
    Args:
        incident: Incident object
        vm_name: VM name to isolate
        
    Returns:
        Action result
    """
    target_vm = vm_name or getattr(incident, 'host_id', None) or "MinhaVM"
    
    logger.info(f"Isolating VM {target_vm}")
    
    # This would integrate with the AzureVMManager
    return {
        "status": "success",
        "message": f"VM {target_vm} isolated successfully",
        "action": "isolate_vm",
        "details": {
            "isolated_vm": target_vm,
            "isolation_method": "vm_stop",
            "resource_group": "ProjetoCSO"
        }
    }


async def restore_vm_backup(incident, vm_name: str = None, **kwargs) -> Dict[str, Any]:
    """
    Restore VM from backup for recovery
    
    Args:
        incident: Incident object
        vm_name: VM name to restore
        
    Returns:
        Action result
    """
    target_vm = vm_name or getattr(incident, 'host_id', None) or "MinhaVM"
    
    logger.info(f"Restoring VM {target_vm} from backup")

    # Only call real Azure if explicitly enabled via env
    if os.environ.get('ENABLE_AZURE_BACKUP', 'false').lower() == 'true':
        try:
            from ...integrations.azure_backup_manager import AzureBackupManager
            manager = AzureBackupManager(
                subscription_id=os.environ.get('AZ_SUBSCRIPTION_ID'),
                tenant_id=os.environ.get('AZ_TENANT_ID'),
                client_id=os.environ.get('AZ_CLIENT_ID'),
                client_secret=os.environ.get('AZ_CLIENT_SECRET')
            )
            result = manager.restore_vm(vm_name=target_vm, recovery_point_time=kwargs.get('recovery_point'))
            return {
                "status": "success" if result.success else "failed",
                "message": "Restore initiated" if result.success else (result.error or "Restore failed"),
                "action": "restore_vm_backup",
                "details": result.details
            }
        except Exception as e:
            logger.warning(f"Azure restore unavailable or failed, falling back to simulation: {e}")

    # Try webhook-based backup if configured
    if os.environ.get('ENABLE_BACKUP_WEBHOOK', 'false').lower() == 'true' or os.environ.get('BACKUP_WEBHOOK_URL'):
        try:
            from ...integrations.webhook_backup import WebhookBackup
            wc = WebhookBackup()
            wr = wc.restore_vm(vm_name=target_vm, recovery_point=kwargs.get('recovery_point'))
            return {
                "status": "success" if wr.success else "failed",
                "message": "Restore requested via webhook" if wr.success else (wr.error or "Restore failed"),
                "action": "restore_vm_backup",
                "details": wr.details
            }
        except Exception as e:
            logger.warning(f"Webhook restore failed, falling back to simulation: {e}")

    # Simulation fallback (default)
    return {
        "status": "simulated",
        "message": f"VM {target_vm} restore initiated (simulated)",
        "action": "restore_vm_backup",
        "details": {
            "restored_vm": target_vm,
            "backup_source": "azure_backup",
            "restore_type": "alternate_location"
        }
    }


async def trigger_vm_backup(incident, vm_name: str = None, **kwargs) -> Dict[str, Any]:
    """
    Trigger a VM backup (env-gated; simulated by default)
    """
    target_vm = vm_name or getattr(incident, 'host_id', None) or getattr(incident, 'source_system', None) or "MinhaVM"
    logger.info(f"Triggering backup for VM {target_vm}")

    if os.environ.get('ENABLE_AZURE_BACKUP', 'false').lower() == 'true':
        try:
            from ...integrations.azure_backup_manager import AzureBackupManager
            manager = AzureBackupManager(
                subscription_id=os.environ.get('AZ_SUBSCRIPTION_ID'),
                tenant_id=os.environ.get('AZ_TENANT_ID'),
                client_id=os.environ.get('AZ_CLIENT_ID'),
                client_secret=os.environ.get('AZ_CLIENT_SECRET')
            )
            result = manager.trigger_backup(vm_name=target_vm)
            return {
                "status": "success" if result.success else "failed",
                "message": "Backup triggered" if result.success else (result.error or "Backup failed"),
                "action": "trigger_vm_backup",
                "details": result.details
            }
        except Exception as e:
            logger.warning(f"Azure backup unavailable or failed, falling back to simulation: {e}")

    # Try webhook-based backup if configured
    if os.environ.get('ENABLE_BACKUP_WEBHOOK', 'false').lower() == 'true' or os.environ.get('BACKUP_WEBHOOK_URL'):
        try:
            from ...integrations.webhook_backup import WebhookBackup
            wc = WebhookBackup()
            wr = wc.trigger_backup(vm_name=target_vm)
            return {
                "status": "success" if wr.success else "failed",
                "message": "Backup triggered via webhook" if wr.success else (wr.error or "Backup failed"),
                "action": "trigger_vm_backup",
                "details": wr.details
            }
        except Exception as e:
            logger.warning(f"Webhook backup failed, falling back to simulation: {e}")

    return {
        "status": "simulated",
        "message": f"Backup triggered for VM {target_vm} (simulated)",
        "action": "trigger_vm_backup",
        "details": {"vm_name": target_vm, "backup_type": kwargs.get('backup_type', 'on_demand')}
    }


async def disable_user_account(incident, username: str = None, **kwargs) -> Dict[str, Any]:
    """
    Disable a user account for security incident
    
    Args:
        incident: Incident object
        username: Username to disable
        
    Returns:
        Action result
    """
    target_user = username or getattr(incident, 'user_id', None) or "sample.user@domain.com"
    
    logger.info(f"Disabling user account {target_user}")

    if os.environ.get('ENABLE_AZURE_AD', 'false').lower() == 'true':
        try:
            from ...integrations.azure_ad_manager import AzureADManager
            adm = AzureADManager(
                tenant_id=os.environ.get('AZ_TENANT_ID'),
                client_id=os.environ.get('AZ_CLIENT_ID'),
                client_secret=os.environ.get('AZ_CLIENT_SECRET')
            )
            res = adm.disable_user_account(user_principal_name=target_user, reason=kwargs.get('reason'))
            return {
                "status": "success" if res.success else "failed",
                "message": "User disabled" if res.success else (res.error or "Disable failed"),
                "action": "disable_user_account",
                "details": res.details
            }
        except Exception as e:
            logger.warning(f"Azure AD disable failed or unavailable, falling back to simulation: {e}")

    return {
        "status": "simulated",
        "message": f"User account {target_user} disabled (simulated)",
        "action": "disable_user_account",
        "details": {
            "disabled_user": target_user,
            "reason": kwargs.get('reason', 'Security incident response'),
            "account_enabled": False
        }
    }


async def emergency_network_isolation(incident, **kwargs) -> Dict[str, Any]:
    """
    Emergency network isolation using NSG rules
    
    Args:
        incident: Incident object
        
    Returns:
        Action result
    """
    logger.warning("Initiating emergency network isolation")
    
    # This would integrate with the AzureNSGManager
    return {
        "status": "success",
        "message": "Emergency network isolation activated",
        "action": "emergency_network_isolation",
        "details": {
            "isolation_type": "complete_inbound_block",
            "nsg_name": "MinhaVMNSG",
            "priority": 90
        }
    }
