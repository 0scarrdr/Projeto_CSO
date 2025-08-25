"""
Recovery actions: restoring systems from backup, cloud snapshots, or EDR rollback.
"""

from soar.utils.logging import get_logger
from soar.integrations.Backup import BackupSystem
from soar.integrations.Cloud import CloudProvider
from soar.integrations.Edr import EDRClient

logger = get_logger(__name__)

backup = BackupSystem()
cloud = CloudProvider()
edr = EDRClient()


def restore_from_backup(host: str):
    logger.info(f"[RECOVERY] A restaurar backup para {host}")
    return backup.restore_backup(host)


def rollback_cloud_vm(vm_id: str):
    logger.info(f"[RECOVERY] A reverter snapshot da VM {vm_id}")
    return cloud.rollback_vm(vm_id)


def edr_rollback(host: str):
    logger.info(f"[RECOVERY] A reverter host {host} via EDR")
    return edr.rollback_host(host)
