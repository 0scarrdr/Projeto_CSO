"""
Azure Virtual Machine Management Integration
Provides comprehensive VM control capabilities for incident response
"""

import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    # Avoid noisy warnings during tests
    if not __name__.endswith('azure_vm_manager') or 'PYTEST_CURRENT_TEST' not in __import__('os').environ:
        logging.warning("Azure SDK not installed. Install with: pip install azure-mgmt-compute azure-identity")

logger = logging.getLogger(__name__)

@dataclass
class VMAction:
    """Represents a VM management action result."""
    action_type: str
    vm_name: str
    resource_group: str
    success: bool
    timestamp: str
    details: Dict[str, Any]
    error: Optional[str] = None

class AzureVMManager:
    """
    Azure Virtual Machine Management for automated incident response
    
    Provides VM control capabilities including:
    - Start/Stop/Restart VMs
    - VM isolation and quarantine
    - Status monitoring
    - Security state management
    """
    
    def __init__(self, subscription_id: str = None, tenant_id: str = None, 
                 client_id: str = None, client_secret: str = None):
        """
        Initialize Azure VM Manager
        
        Args:
            subscription_id: Azure subscription ID
            tenant_id: Azure tenant ID
            client_id: Azure client ID for service principal
            client_secret: Azure client secret
        """
        if not AZURE_AVAILABLE:
            # Degrade gracefully in test environments
            self.initialized = False
            logger.warning("Azure SDK not available; AzureVMManager running in dummy mode")
            return
            
        # Use provided credentials or environment variables
        self.subscription_id = subscription_id or "405650f3-310c-4f72-b8ea-81e0c5764c85"
        self.tenant_id = tenant_id or "6bfdb318-8dfa-4d4c-ae55-c0862aa6a5b1"
        self.client_id = client_id or "cc361287-4039-4a65-bdbf-864068f04525"
        self.client_secret = client_secret
        
        self.credential = None
        self.compute_client = None
        self.resource_client = None
        self.initialized = False
        
        logger.info("AzureVMManager initialized")
    
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
                from azure.identity import DefaultAzureCredential
                self.credential = DefaultAzureCredential()
            
            # Initialize clients
            self.compute_client = ComputeManagementClient(
                self.credential, 
                self.subscription_id
            )
            self.resource_client = ResourceManagementClient(
                self.credential,
                self.subscription_id
            )
            
            # Test connection by listing resource groups
            resource_groups = list(self.resource_client.resource_groups.list())
            logger.info(f"Connected to Azure. Found {len(resource_groups)} resource groups")
            
            self.initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Azure VM Manager: {e}")
            return False
    
    def stop_vm(self, vm_name: str, resource_group: str = "ProjetoCSO") -> VMAction:
        """
        Stop a virtual machine for incident containment
        
        Args:
            vm_name: Name of the VM to stop
            resource_group: Resource group containing the VM
            
        Returns:
            VMAction result
        """
        if not self.initialized:
            if not self.initialize():
                return VMAction(
                    action_type="stop_vm",
                    vm_name=vm_name,
                    resource_group=resource_group,
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure client not initialized"
                )
        
        try:
            logger.info(f"Stopping VM {vm_name} in resource group {resource_group}")
            
            # Stop the VM
            operation = self.compute_client.virtual_machines.begin_deallocate(
                resource_group_name=resource_group,
                vm_name=vm_name
            )
            
            # Wait for completion
            result = operation.result()
            
            logger.info(f"VM {vm_name} stopped successfully")
            
            return VMAction(
                action_type="stop_vm",
                vm_name=vm_name,
                resource_group=resource_group,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "operation_id": operation.polling_method()._pipeline_response.http_response.headers.get('Azure-AsyncOperation', ''),
                    "status": "stopped"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to stop VM {vm_name}: {e}")
            return VMAction(
                action_type="stop_vm",
                vm_name=vm_name,
                resource_group=resource_group,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={},
                error=str(e)
            )
    
    def start_vm(self, vm_name: str, resource_group: str = "ProjetoCSO") -> VMAction:
        """
        Start a virtual machine for recovery operations
        
        Args:
            vm_name: Name of the VM to start
            resource_group: Resource group containing the VM
            
        Returns:
            VMAction result
        """
        if not self.initialized:
            if not self.initialize():
                return VMAction(
                    action_type="start_vm",
                    vm_name=vm_name,
                    resource_group=resource_group,
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure client not initialized"
                )
        
        try:
            logger.info(f"Starting VM {vm_name} in resource group {resource_group}")
            
            # Start the VM
            operation = self.compute_client.virtual_machines.begin_start(
                resource_group_name=resource_group,
                vm_name=vm_name
            )
            
            # Wait for completion
            result = operation.result()
            
            logger.info(f"VM {vm_name} started successfully")
            
            return VMAction(
                action_type="start_vm",
                vm_name=vm_name,
                resource_group=resource_group,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "operation_id": operation.polling_method()._pipeline_response.http_response.headers.get('Azure-AsyncOperation', ''),
                    "status": "running"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to start VM {vm_name}: {e}")
            return VMAction(
                action_type="start_vm",
                vm_name=vm_name,
                resource_group=resource_group,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={},
                error=str(e)
            )
    
    def restart_vm(self, vm_name: str, resource_group: str = "ProjetoCSO") -> VMAction:
        """
        Restart a virtual machine for recovery operations
        
        Args:
            vm_name: Name of the VM to restart
            resource_group: Resource group containing the VM
            
        Returns:
            VMAction result
        """
        if not self.initialized:
            if not self.initialize():
                return VMAction(
                    action_type="restart_vm",
                    vm_name=vm_name,
                    resource_group=resource_group,
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure client not initialized"
                )
        
        try:
            logger.info(f"Restarting VM {vm_name} in resource group {resource_group}")
            
            # Restart the VM
            operation = self.compute_client.virtual_machines.begin_restart(
                resource_group_name=resource_group,
                vm_name=vm_name
            )
            
            # Wait for completion
            result = operation.result()
            
            logger.info(f"VM {vm_name} restarted successfully")
            
            return VMAction(
                action_type="restart_vm",
                vm_name=vm_name,
                resource_group=resource_group,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "operation_id": operation.polling_method()._pipeline_response.http_response.headers.get('Azure-AsyncOperation', ''),
                    "status": "restarted"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to restart VM {vm_name}: {e}")
            return VMAction(
                action_type="restart_vm",
                vm_name=vm_name,
                resource_group=resource_group,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={},
                error=str(e)
            )
    
    def get_vm_status(self, vm_name: str, resource_group: str = "ProjetoCSO") -> Dict[str, Any]:
        """
        Get current status of a virtual machine
        
        Args:
            vm_name: Name of the VM
            resource_group: Resource group containing the VM
            
        Returns:
            VM status information
        """
        if not self.initialized:
            if not self.initialize():
                return {
                    "success": False,
                    "error": "Azure client not initialized"
                }
        
        try:
            # Get VM instance view
            vm_instance = self.compute_client.virtual_machines.instance_view(
                resource_group_name=resource_group,
                vm_name=vm_name
            )
            
            # Get VM details
            vm_details = self.compute_client.virtual_machines.get(
                resource_group_name=resource_group,
                vm_name=vm_name
            )
            
            power_state = "unknown"
            for status in vm_instance.statuses:
                if status.code.startswith('PowerState/'):
                    power_state = status.code.split('/')[-1]
                    break
            
            return {
                "success": True,
                "vm_name": vm_name,
                "resource_group": resource_group,
                "power_state": power_state,
                "vm_size": vm_details.hardware_profile.vm_size,
                "os_type": vm_details.storage_profile.os_disk.os_type.name if vm_details.storage_profile.os_disk.os_type else "unknown",
                "location": vm_details.location,
                "statuses": [{"code": s.code, "display_status": s.display_status} for s in vm_instance.statuses]
            }
            
        except Exception as e:
            logger.error(f"Failed to get VM status for {vm_name}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def isolate_vm(self, vm_name: str, resource_group: str = "ProjetoCSO") -> VMAction:
        """
        Isolate a compromised VM by stopping it
        This can be extended to include network isolation via NSG rules
        
        Args:
            vm_name: Name of the VM to isolate
            resource_group: Resource group containing the VM
            
        Returns:
            VMAction result
        """
        logger.info(f"Isolating VM {vm_name} due to security incident")
        
        # For now, isolation means stopping the VM
        # This can be extended to include network isolation
        result = self.stop_vm(vm_name, resource_group)
        result.action_type = "isolate_vm"
        
        if result.success:
            logger.info(f"VM {vm_name} successfully isolated")
        else:
            logger.error(f"Failed to isolate VM {vm_name}: {result.error}")
        
        return result
