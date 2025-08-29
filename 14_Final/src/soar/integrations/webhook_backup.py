"""
Webhook-based Backup Integration

Allows triggering backups and restores via HTTP endpoints for any provider.
Useful when native SDKs are unavailable; pairs with env flags to enable safely.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class BackupWebhookResult:
    success: bool
    details: Dict[str, Any]
    error: Optional[str] = None


class WebhookBackup:
    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None, timeout: int = 15):
        self.base_url = (base_url or os.environ.get("BACKUP_WEBHOOK_URL") or "").rstrip("/")
        self.api_key = api_key or os.environ.get("BACKUP_WEBHOOK_KEY")
        self.timeout = timeout
        if not self.base_url:
            logger.warning("WebhookBackup base URL not configured; calls will fail until set")

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def trigger_backup(self, vm_name: str) -> BackupWebhookResult:
        try:
            url = f"{self.base_url}/backup/trigger"
            r = requests.post(url, json={"vm_name": vm_name}, headers=self._headers(), timeout=self.timeout)
            ok = r.status_code // 100 == 2
            return BackupWebhookResult(success=ok, details=r.json() if ok else {"status_code": r.status_code}, error=None if ok else r.text)
        except Exception as e:
            logger.error(f"WebhookBackup trigger failed: {e}")
            return BackupWebhookResult(success=False, details={}, error=str(e))

    def restore_vm(self, vm_name: str, recovery_point: Optional[str] = None) -> BackupWebhookResult:
        try:
            url = f"{self.base_url}/backup/restore"
            payload = {"vm_name": vm_name, "recovery_point": recovery_point}
            r = requests.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            ok = r.status_code // 100 == 2
            return BackupWebhookResult(success=ok, details=r.json() if ok else {"status_code": r.status_code}, error=None if ok else r.text)
        except Exception as e:
            logger.error(f"WebhookBackup restore failed: {e}")
            return BackupWebhookResult(success=False, details={}, error=str(e))
