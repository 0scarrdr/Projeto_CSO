"""
External integrations module for SOAR system
Provides integration with external services including SIEM, cloud providers, and threat intelligence
"""

from .siem_connector import SIEMConnector
from .threat_intel_client import ThreatIntelligenceClient
from .azure_firewall_manager import AzureFirewallManager
from .azure_vm_manager import AzureVMManager
from .azure_nsg_manager import AzureNSGManager
from .azure_backup_manager import AzureBackupManager
from .azure_ad_manager import AzureADManager

__all__ = [
    'SIEMConnector',
    'ThreatIntelligenceClient', 
    'AzureFirewallManager',
    'AzureVMManager',
    'AzureNSGManager',
    'AzureBackupManager',
    'AzureADManager'
]
