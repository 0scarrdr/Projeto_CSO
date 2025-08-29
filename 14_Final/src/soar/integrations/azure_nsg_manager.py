"""
Azure Network Security Group Management
Provides network segmentation and isolation capabilities for incident response
"""

import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

try:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.network.models import (
        SecurityRule,
        SecurityRuleProtocol,
        SecurityRuleAccess,
        SecurityRuleDirection
    )
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    logging.warning("Azure SDK not installed. Install with: pip install azure-mgmt-network azure-identity")

logger = logging.getLogger(__name__)

@dataclass
class NSGAction:
    """Represents a Network Security Group action result."""
    action_type: str
    nsg_name: str
    resource_group: str
    success: bool
    timestamp: str
    details: Dict[str, Any]
    error: Optional[str] = None

class AzureNSGManager:
    """
    Azure Network Security Group Manager for network segmentation
    
    Provides network isolation capabilities including:
    - Block/Allow IP addresses
    - Port blocking/opening
    - Emergency network isolation
    - Traffic analysis and monitoring
    """
    
    def __init__(self, subscription_id: str = None, tenant_id: str = None, 
                 client_id: str = None, client_secret: str = None):
        """
        Initialize Azure NSG Manager
        
        Args:
            subscription_id: Azure subscription ID
            tenant_id: Azure tenant ID
            client_id: Azure client ID for service principal
            client_secret: Azure client secret
        """
        if not AZURE_AVAILABLE:
            raise ImportError("Azure SDK not available")
            
        # Use provided credentials or environment variables
        self.subscription_id = subscription_id or "405650f3-310c-4f72-b8ea-81e0c5764c85"
        self.tenant_id = tenant_id or "6bfdb318-8dfa-4d4c-ae55-c0862aa6a5b1"
        self.client_id = client_id or "cc361287-4039-4a65-bdbf-864068f04525"
        self.client_secret = client_secret
        
        self.credential = None
        self.network_client = None
        self.initialized = False
        
        # Known NSGs from the environment
        self.known_nsgs = ["MeuNSGV", "MinhaVMNSG"]
        self.default_resource_group = "ProjetoCSO"
        
        logger.info("AzureNSGManager initialized")
    
    def initialize(self) -> bool:
        """Initialize Azure clients and test connection"""
        try:
            # Create credential
            if self.client_secret:
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
            else:
                self.credential = DefaultAzureCredential()
            
            # Initialize network client
            self.network_client = NetworkManagementClient(
                self.credential, 
                self.subscription_id
            )
            
            # Test connection by listing NSGs
            nsgs = list(self.network_client.network_security_groups.list_all())
            logger.info(f"Connected to Azure Network. Found {len(nsgs)} NSGs")
            
            self.initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Azure NSG Manager: {e}")
            return False
    
    def block_ip_address(self, ip_address: str, nsg_name: str = "MinhaVMNSG", 
                        resource_group: str = "ProjetoCSO", priority: int = 100) -> NSGAction:
        """
        Block an IP address by creating a deny rule in NSG
        
        Args:
            ip_address: IP address to block
            nsg_name: NSG name to add the rule to
            resource_group: Resource group containing the NSG
            priority: Rule priority (lower number = higher priority)
            
        Returns:
            NSGAction result
        """
        if not self.initialized:
            if not self.initialize():
                return NSGAction(
                    action_type="block_ip",
                    nsg_name=nsg_name,
                    resource_group=resource_group,
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure client not initialized"
                )
        
        try:
            rule_name = f"SOAR_Block_{ip_address.replace('.', '_')}_{int(datetime.now().timestamp())}"
            
            logger.info(f"Creating block rule for IP {ip_address} in NSG {nsg_name}")
            
            # Create the security rule
            security_rule = SecurityRule(
                name=rule_name,
                protocol=SecurityRuleProtocol.ASTERISK,
                source_address_prefix=ip_address,
                source_port_range="*",
                destination_address_prefix="*",
                destination_port_range="*",
                access=SecurityRuleAccess.DENY,
                direction=SecurityRuleDirection.INBOUND,
                priority=priority,
                description=f"SOAR Automated Block - Incident Response {datetime.now().isoformat()}"
            )
            
            # Add the rule to NSG
            operation = self.network_client.security_rules.begin_create_or_update(
                resource_group_name=resource_group,
                network_security_group_name=nsg_name,
                security_rule_name=rule_name,
                security_rule_parameters=security_rule
            )
            
            # Wait for completion
            result = operation.result()
            
            logger.info(f"Successfully created block rule {rule_name} for IP {ip_address}")
            
            return NSGAction(
                action_type="block_ip",
                nsg_name=nsg_name,
                resource_group=resource_group,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "rule_name": rule_name,
                    "blocked_ip": ip_address,
                    "priority": priority,
                    "direction": "inbound",
                    "access": "deny"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")
            return NSGAction(
                action_type="block_ip",
                nsg_name=nsg_name,
                resource_group=resource_group,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={"ip_address": ip_address},
                error=str(e)
            )
    
    def block_port(self, port: int, nsg_name: str = "MinhaVMNSG", 
                   resource_group: str = "ProjetoCSO", priority: int = 150) -> NSGAction:
        """
        Block a specific port by creating a deny rule in NSG
        
        Args:
            port: Port number to block
            nsg_name: NSG name to add the rule to
            resource_group: Resource group containing the NSG
            priority: Rule priority
            
        Returns:
            NSGAction result
        """
        if not self.initialized:
            if not self.initialize():
                return NSGAction(
                    action_type="block_port",
                    nsg_name=nsg_name,
                    resource_group=resource_group,
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure client not initialized"
                )
        
        try:
            rule_name = f"SOAR_Block_Port_{port}_{int(datetime.now().timestamp())}"
            
            logger.info(f"Creating block rule for port {port} in NSG {nsg_name}")
            
            # Create the security rule
            security_rule = SecurityRule(
                name=rule_name,
                protocol=SecurityRuleProtocol.ASTERISK,
                source_address_prefix="*",
                source_port_range="*",
                destination_address_prefix="*",
                destination_port_range=str(port),
                access=SecurityRuleAccess.DENY,
                direction=SecurityRuleDirection.INBOUND,
                priority=priority,
                description=f"SOAR Automated Port Block - Incident Response {datetime.now().isoformat()}"
            )
            
            # Add the rule to NSG
            operation = self.network_client.security_rules.begin_create_or_update(
                resource_group_name=resource_group,
                network_security_group_name=nsg_name,
                security_rule_name=rule_name,
                security_rule_parameters=security_rule
            )
            
            # Wait for completion
            result = operation.result()
            
            logger.info(f"Successfully created block rule {rule_name} for port {port}")
            
            return NSGAction(
                action_type="block_port",
                nsg_name=nsg_name,
                resource_group=resource_group,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "rule_name": rule_name,
                    "blocked_port": port,
                    "priority": priority,
                    "direction": "inbound",
                    "access": "deny"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to block port {port}: {e}")
            return NSGAction(
                action_type="block_port",
                nsg_name=nsg_name,
                resource_group=resource_group,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={"port": port},
                error=str(e)
            )
    
    def emergency_isolation(self, nsg_name: str = "MinhaVMNSG", 
                           resource_group: str = "ProjetoCSO") -> NSGAction:
        """
        Create emergency isolation by blocking all inbound traffic
        
        Args:
            nsg_name: NSG name to isolate
            resource_group: Resource group containing the NSG
            
        Returns:
            NSGAction result
        """
        if not self.initialized:
            if not self.initialize():
                return NSGAction(
                    action_type="emergency_isolation",
                    nsg_name=nsg_name,
                    resource_group=resource_group,
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure client not initialized"
                )
        
        try:
            rule_name = f"SOAR_Emergency_Isolation_{int(datetime.now().timestamp())}"
            
            logger.info(f"Creating emergency isolation rule in NSG {nsg_name}")
            
            # Create the emergency isolation rule (highest priority)
            security_rule = SecurityRule(
                name=rule_name,
                protocol=SecurityRuleProtocol.ASTERISK,
                source_address_prefix="*",
                source_port_range="*",
                destination_address_prefix="*",
                destination_port_range="*",
                access=SecurityRuleAccess.DENY,
                direction=SecurityRuleDirection.INBOUND,
                priority=90,  # Very high priority
                description=f"SOAR Emergency Isolation - Critical Incident {datetime.now().isoformat()}"
            )
            
            # Add the rule to NSG
            operation = self.network_client.security_rules.begin_create_or_update(
                resource_group_name=resource_group,
                network_security_group_name=nsg_name,
                security_rule_name=rule_name,
                security_rule_parameters=security_rule
            )
            
            # Wait for completion
            result = operation.result()
            
            logger.warning(f"Emergency isolation activated for NSG {nsg_name} - Rule: {rule_name}")
            
            return NSGAction(
                action_type="emergency_isolation",
                nsg_name=nsg_name,
                resource_group=resource_group,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "rule_name": rule_name,
                    "priority": 90,
                    "isolation_type": "complete_inbound_block",
                    "direction": "inbound",
                    "access": "deny"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to create emergency isolation for NSG {nsg_name}: {e}")
            return NSGAction(
                action_type="emergency_isolation",
                nsg_name=nsg_name,
                resource_group=resource_group,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={},
                error=str(e)
            )
    
    def remove_block_rule(self, rule_name: str, nsg_name: str = "MinhaVMNSG", 
                         resource_group: str = "ProjetoCSO") -> NSGAction:
        """
        Remove a blocking rule from NSG (for recovery)
        
        Args:
            rule_name: Name of the rule to remove
            nsg_name: NSG name containing the rule
            resource_group: Resource group containing the NSG
            
        Returns:
            NSGAction result
        """
        if not self.initialized:
            if not self.initialize():
                return NSGAction(
                    action_type="remove_block_rule",
                    nsg_name=nsg_name,
                    resource_group=resource_group,
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure client not initialized"
                )
        
        try:
            logger.info(f"Removing block rule {rule_name} from NSG {nsg_name}")
            
            # Remove the rule
            operation = self.network_client.security_rules.begin_delete(
                resource_group_name=resource_group,
                network_security_group_name=nsg_name,
                security_rule_name=rule_name
            )
            
            # Wait for completion
            operation.result()
            
            logger.info(f"Successfully removed block rule {rule_name}")
            
            return NSGAction(
                action_type="remove_block_rule",
                nsg_name=nsg_name,
                resource_group=resource_group,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "removed_rule": rule_name
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to remove rule {rule_name}: {e}")
            return NSGAction(
                action_type="remove_block_rule",
                nsg_name=nsg_name,
                resource_group=resource_group,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={"rule_name": rule_name},
                error=str(e)
            )
    
    def list_security_rules(self, nsg_name: str = "MinhaVMNSG", 
                           resource_group: str = "ProjetoCSO") -> Dict[str, Any]:
        """
        List all security rules in an NSG
        
        Args:
            nsg_name: NSG name
            resource_group: Resource group containing the NSG
            
        Returns:
            Dictionary with rules information
        """
        if not self.initialized:
            if not self.initialize():
                return {
                    "success": False,
                    "error": "Azure client not initialized"
                }
        
        try:
            logger.info(f"Listing security rules for NSG {nsg_name}")
            
            # Get NSG with rules
            nsg = self.network_client.network_security_groups.get(
                resource_group_name=resource_group,
                network_security_group_name=nsg_name
            )
            
            rules = []
            if nsg.security_rules:
                for rule in nsg.security_rules:
                    rules.append({
                        "name": rule.name,
                        "priority": rule.priority,
                        "direction": rule.direction,
                        "access": rule.access,
                        "protocol": rule.protocol,
                        "source_address_prefix": rule.source_address_prefix,
                        "source_port_range": rule.source_port_range,
                        "destination_address_prefix": rule.destination_address_prefix,
                        "destination_port_range": rule.destination_port_range,
                        "description": rule.description
                    })
            
            return {
                "success": True,
                "nsg_name": nsg_name,
                "resource_group": resource_group,
                "rules_count": len(rules),
                "rules": rules
            }
            
        except Exception as e:
            logger.error(f"Failed to list rules for NSG {nsg_name}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
