"""
Webhook-based EDR Integration

Allows delegating EDR actions to any external service via simple HTTP webhooks.
Useful when vendor EDR (e.g., Wazuh/Defender) is unavailable in the environment.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class EDRWebhookResult:
    success: bool
    details: Dict[str, Any]
    error: Optional[str] = None


class WebhookEDR:
    """Simple webhook client for EDR-like actions."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None, timeout: int = 10):
        self.base_url = (base_url or os.environ.get("EDR_WEBHOOK_URL") or "").rstrip("/")
        self.api_key = api_key or os.environ.get("EDR_WEBHOOK_KEY")
        self.timeout = timeout
        if not self.base_url:
            logger.warning("WebhookEDR base URL not configured; calls will fail until set")

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def isolate_machine(self, machine_name: Optional[str] = None, isolation_type: str = "Full") -> EDRWebhookResult:
        try:
            url = f"{self.base_url}/edr/isolate"
            payload = {"machine_name": machine_name, "isolation_type": isolation_type}
            r = requests.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            ok = r.status_code // 100 == 2
            return EDRWebhookResult(success=ok, details=r.json() if ok else {"status_code": r.status_code}, error=None if ok else r.text)
        except Exception as e:
            logger.error(f"WebhookEDR isolate failed: {e}")
            return EDRWebhookResult(success=False, details={}, error=str(e))

    def unisolate_machine(self, machine_name: Optional[str] = None) -> EDRWebhookResult:
        try:
            url = f"{self.base_url}/edr/unisolate"
            payload = {"machine_name": machine_name}
            r = requests.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            ok = r.status_code // 100 == 2
            return EDRWebhookResult(success=ok, details=r.json() if ok else {"status_code": r.status_code}, error=None if ok else r.text)
        except Exception as e:
            logger.error(f"WebhookEDR unisolate failed: {e}")
            return EDRWebhookResult(success=False, details={}, error=str(e))

    def run_scan(self, machine_name: Optional[str] = None, scan_type: str = "Quick") -> EDRWebhookResult:
        try:
            url = f"{self.base_url}/edr/scan"
            payload = {"machine_name": machine_name, "scan_type": scan_type}
            r = requests.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            ok = r.status_code // 100 == 2
            return EDRWebhookResult(success=ok, details=r.json() if ok else {"status_code": r.status_code}, error=None if ok else r.text)
        except Exception as e:
            logger.error(f"WebhookEDR scan failed: {e}")
            return EDRWebhookResult(success=False, details={}, error=str(e))
