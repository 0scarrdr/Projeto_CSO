"""Azure Firewall integration for automated network security control - WORKING VERSION."""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

try:
    from dotenv import load_dotenv
    load_dotenv()  # This loads .env file
except ImportError:
    pass


# Azure SDK imports - SYNCHRONOUS VERSION
try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.network.models import (
        AzureFirewallNetworkRuleCollection,
        AzureFirewallNetworkRule,
        AzureFirewallRCAction
    )
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    # Keep quiet during tests to avoid noisy output
    if not os.getenv('PYTEST_CURRENT_TEST'):
        logging.warning("Azure SDK not installed. Install with: pip install azure-mgmt-network azure-identity")

logger = logging.getLogger(__name__)

@dataclass
class FirewallAction:
    """Represents a firewall action result."""
    action_type: str
    target: str
    success: bool
    rule_name: str
    timestamp: str
    details: Dict[str, Any]
    error: Optional[str] = None
    
    def get(self, key: str, default=None):
        """Provide dict-like access for compatibility."""
        return getattr(self, key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

class AzureFirewallManager:
    """Manager for Azure Firewall operations - WORKING VERSION."""
    
    def __init__(self, 
                 subscription_id: str = None,
                 tenant_id: str = None, 
                 client_id: str = None,
                 client_secret: str = None,
                 resource_group: str = None,
                 firewall_name: str = None):
        """Initialize Azure Firewall manager."""
        
        # Load from environment if not provided
        self.subscription_id = subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
        self.tenant_id = tenant_id or os.getenv('AZURE_TENANT_ID')
        self.client_id = client_id or os.getenv('AZURE_CLIENT_ID')
        self.client_secret = client_secret or os.getenv('AZURE_CLIENT_SECRET')
        self.resource_group = resource_group or os.getenv('AZURE_RESOURCE_GROUP')
        self.firewall_name = firewall_name or os.getenv('AZURE_FIREWALL_NAME')
        
        self.credential = None
        self.network_client = None
        self.logger = logger
        self.blocked_ips_cache = set()
        self._initialized = False
        
        # Validate configuration
        if not AZURE_AVAILABLE:
            self.logger.error("Azure SDK not available")
            return
            
        if not all([self.subscription_id, self.tenant_id, self.client_id, 
                   self.client_secret, self.resource_group, self.firewall_name]):
            self.logger.warning("Azure Firewall configuration incomplete")
    
    def initialize(self) -> bool:
        """Initialize Azure clients and test connection - SYNCHRONOUS."""
        try:
            if not AZURE_AVAILABLE:
                self.logger.error("Azure SDK not available")
                return False
            
            if self._initialized:
                return True
            
            self.logger.info("Initializing Azure Firewall manager...")
            
            # Create credential
            self.credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            
            # Create network client
            self.network_client = NetworkManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
            
            # Test connection by getting firewall info
            firewall_info = self._get_firewall_info()
            if firewall_info:
                self.logger.info(f"Azure Firewall manager initialized: {self.firewall_name}")
                self._initialized = True
                return True
            else:
                self.logger.error("Failed to connect to Azure Firewall")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to initialize Azure Firewall manager: {e}")
            return False
    
    def _get_firewall_info(self) -> Optional[Dict[str, Any]]:
        """Get Azure Firewall information - SYNCHRONOUS."""
        try:
            self.logger.debug(f"Getting firewall info for: {self.firewall_name}")
            
            firewall = self.network_client.azure_firewalls.get(
                resource_group_name=self.resource_group,
                azure_firewall_name=self.firewall_name
            )
            
            return {
                "name": firewall.name,
                "location": firewall.location,
                "provisioning_state": firewall.provisioning_state,
                "threat_intel_mode": getattr(firewall, 'threat_intel_mode', 'Unknown'),
                "application_rule_collections": len(firewall.application_rule_collections or []),
                "network_rule_collections": len(firewall.network_rule_collections or []),
                "nat_rule_collections": len(firewall.nat_rule_collections or [])
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get firewall info: {e}")
            return None
    
    def block_ip_address(self, ip_address: str, reason: str = "SOAR Auto-Block", 
                        priority: int = 100, incident_id: str = None) -> FirewallAction:
        """Block an IP address through Azure Firewall network rules - SYNCHRONOUS."""
        try:
            if not self._initialized:
                if not self.initialize():
                    return FirewallAction(
                        action_type="block_ip",
                        target=ip_address,
                        success=False,
                        rule_name="",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        details={},
                        error="Azure Firewall not initialized"
                    )
            
            self.logger.info(f"Blocking IP address: {ip_address} (Reason: {reason})")
            
            # Generate unique rule name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rule_collection_name = "SOAR-Block-Collection"
            rule_name = f"Block-{ip_address.replace('.', '-')}-{timestamp}"
            
            # Get current firewall configuration
            firewall = self.network_client.azure_firewalls.get(
                resource_group_name=self.resource_group,
                azure_firewall_name=self.firewall_name
            )
            
            # Find or create SOAR rule collection
            soar_collection = None
            for collection in firewall.network_rule_collections or []:
                if collection.name == rule_collection_name:
                    soar_collection = collection
                    break
            
            if not soar_collection:
                # Create new rule collection
                soar_collection = AzureFirewallNetworkRuleCollection(
                    name=rule_collection_name,
                    priority=priority,
                    action=AzureFirewallRCAction(type="Deny"),
                    rules=[]
                )
                
                if not firewall.network_rule_collections:
                    firewall.network_rule_collections = []
                firewall.network_rule_collections.append(soar_collection)
            
            # Create new blocking rule
            rule_description = f"{reason}"
            if incident_id:
                rule_description += f" - Incident: {incident_id}"
            rule_description += f" - Blocked by SOAR at {datetime.now().isoformat()}"
            
            new_rule = AzureFirewallNetworkRule(
                name=rule_name,
                description=rule_description,
                source_addresses=["*"],
                destination_addresses=[ip_address],
                destination_ports=["*"],
                protocols=["Any"]
            )
            
            # Add rule to collection
            if not soar_collection.rules:
                soar_collection.rules = []
            soar_collection.rules.append(new_rule)
            
            # Update firewall
            self.logger.info(f"Updating Azure Firewall with new rule: {rule_name}")
            
            # This operation can take several minutes
            poller = self.network_client.azure_firewalls.begin_create_or_update(
                resource_group_name=self.resource_group,
                azure_firewall_name=self.firewall_name,
                parameters=firewall
            )
            
            # Wait for completion with timeout
            self.logger.info("Waiting for Azure Firewall update to complete...")
            result = poller.result(timeout=300)  # 5 minute timeout
            
            # Add to local cache
            self.blocked_ips_cache.add(ip_address)
            
            return FirewallAction(
                action_type="block_ip",
                target=ip_address,
                success=True,
                rule_name=rule_name,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "reason": reason,
                    "incident_id": incident_id,
                    "priority": priority,
                    "collection": rule_collection_name,
                    "azure_operation": "create_or_update_firewall"
                }
            )
            
        except Exception as e:
            self.logger.error(f"Failed to block IP {ip_address}: {e}")
            return FirewallAction(
                action_type="block_ip",
                target=ip_address,
                success=False,
                rule_name="",
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={},
                error=str(e)
            )
    
    def unblock_ip_address(self, ip_address: str, reason: str = "SOAR Auto-Unblock") -> FirewallAction:
        """Unblock an IP address by removing firewall rules - SYNCHRONOUS."""
        try:
            if not self._initialized:
                if not self.initialize():
                    return FirewallAction(
                        action_type="unblock_ip",
                        target=ip_address,
                        success=False,
                        rule_name="",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        details={},
                        error="Azure Firewall not initialized"
                    )
            
            self.logger.info(f"Unblocking IP address: {ip_address}")
            
            # Get current firewall configuration
            firewall = self.network_client.azure_firewalls.get(
                resource_group_name=self.resource_group,
                azure_firewall_name=self.firewall_name
            )
            
            removed_rules = []
            
            # Find and remove rules for this IP
            for collection in firewall.network_rule_collections or []:
                if collection.name.startswith("SOAR-"):
                    rules_to_keep = []
                    for rule in collection.rules or []:
                        if ip_address not in (rule.destination_addresses or []):
                            rules_to_keep.append(rule)
                        else:
                            removed_rules.append(rule.name)
                    
                    collection.rules = rules_to_keep
            
            if removed_rules:
                # Update firewall
                poller = self.network_client.azure_firewalls.begin_create_or_update(
                    resource_group_name=self.resource_group,
                    azure_firewall_name=self.firewall_name,
                    parameters=firewall
                )
                
                result = poller.result(timeout=300)
                
                # Remove from local cache
                self.blocked_ips_cache.discard(ip_address)
                
                return FirewallAction(
                    action_type="unblock_ip",
                    target=ip_address,
                    success=True,
                    rule_name=", ".join(removed_rules),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={
                        "reason": reason,
                        "removed_rules": removed_rules,
                        "azure_operation": "create_or_update_firewall"
                    }
                )
            else:
                return FirewallAction(
                    action_type="unblock_ip",
                    target=ip_address,
                    success=True,
                    rule_name="",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={"message": "No rules found for IP"},
                    error="IP not currently blocked"
                )
                
        except Exception as e:
            self.logger.error(f"Failed to unblock IP {ip_address}: {e}")
            return FirewallAction(
                action_type="unblock_ip",
                target=ip_address,
                success=False,
                rule_name="",
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={},
                error=str(e)
            )
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IP addresses - SYNCHRONOUS."""
        try:
            if not self._initialized:
                if not self.initialize():
                    return []
            
            firewall = self.network_client.azure_firewalls.get(
                resource_group_name=self.resource_group,
                azure_firewall_name=self.firewall_name
            )
            
            blocked_ips = set()
            
            # Parse all SOAR-created rules
            for collection in firewall.network_rule_collections or []:
                if collection.name.startswith("SOAR-") and collection.action.type == "Deny":
                    for rule in collection.rules or []:
                        for dest_addr in rule.destination_addresses or []:
                            if self._is_valid_ip(dest_addr):
                                blocked_ips.add(dest_addr)
            
            return list(blocked_ips)
            
        except Exception as e:
            self.logger.error(f"Failed to get blocked IPs: {e}")
            return []
    
    def _is_valid_ip(self, ip_string: str) -> bool:
        """Validate if string is a valid IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    def get_firewall_status(self) -> Dict[str, Any]:
        """Get comprehensive firewall status - SYNCHRONOUS."""
        try:
            if not self._initialized:
                if not self.initialize():
                    return {
                        "status": "error",
                        "error": "Not initialized",
                        "last_checked": datetime.now(timezone.utc).isoformat()
                    }
            
            firewall_info = self._get_firewall_info()
            blocked_ips = self.get_blocked_ips()
            
            return {
                "firewall_info": firewall_info,
                "blocked_ips_count": len(blocked_ips),
                "blocked_ips": blocked_ips[:10],  # First 10 for summary
                "cache_size": len(self.blocked_ips_cache),
                "status": "operational" if firewall_info else "error",
                "last_checked": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get firewall status: {e}")
            return {
                "status": "error",
                "error": str(e),
                "last_checked": datetime.now(timezone.utc).isoformat()
            }
    
    def emergency_unblock_all_soar_rules(self) -> Dict[str, Any]:
        """Emergency function to remove all SOAR-created rules - SYNCHRONOUS."""
        try:
            if not self._initialized:
                if not self.initialize():
                    return {
                        "success": False,
                        "error": "Not initialized",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
            
            self.logger.warning("EMERGENCY: Removing all SOAR firewall rules")
            
            firewall = self.network_client.azure_firewalls.get(
                resource_group_name=self.resource_group,
                azure_firewall_name=self.firewall_name
            )
            
            # Remove all SOAR collections
            original_count = len(firewall.network_rule_collections or [])
            
            firewall.network_rule_collections = [
                collection for collection in (firewall.network_rule_collections or [])
                if not collection.name.startswith("SOAR-")
            ]
            
            removed_count = original_count - len(firewall.network_rule_collections)
            
            if removed_count > 0:
                poller = self.network_client.azure_firewalls.begin_create_or_update(
                    resource_group_name=self.resource_group,
                    azure_firewall_name=self.firewall_name,
                    parameters=firewall
                )
                
                result = poller.result(timeout=300)
                
                # Clear cache
                self.blocked_ips_cache.clear()
            
            return {
                "success": True,
                "removed_collections": removed_count,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Emergency unblock failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def close(self):
        """Close Azure clients - SYNCHRONOUS."""
        try:
            if self.network_client:
                self.network_client.close()
            if self.credential:
                # Synchronous credential doesn't need explicit close
                pass
        except Exception as e:
            self.logger.error(f"Error closing Azure clients: {e}")