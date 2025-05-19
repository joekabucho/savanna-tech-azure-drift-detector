"""
Virtual Machine poller module for Azure.

This module provides functionality for polling Azure Virtual Machine configurations.
"""

import logging
from .base import BasePoller

logger = logging.getLogger(__name__)

class VMPoller(BasePoller):
    """
    Poller for Azure Virtual Machine resources.
    
    This class handles polling of VM configurations including:
    - VM properties and settings
    - Network interfaces
    - Disks
    - Extensions
    """
    
    def poll(self):
        """
        Poll all VMs in the subscription.
        
        Returns:
            bool: True if polling was successful, False otherwise
        """
        try:
            # Get all VMs in the subscription
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01"
            vms = self.make_request(url)
            
            if not vms or 'value' not in vms:
                logger.warning("No VMs found or invalid response")
                return False
            
            for vm in vms['value']:
                self._poll_vm_details(vm)
            
            return True
            
        except Exception as e:
            logger.exception(f"Error polling VMs: {str(e)}")
            return False
    
    def _poll_vm_details(self, vm):
        """
        Poll detailed configuration for a specific VM.
        
        Args:
            vm (dict): Basic VM information from list call
        """
        try:
            vm_id = vm['id']
            vm_name = vm['name']
            
            # Get detailed VM configuration
            vm_details = self.make_request(f"{vm_id}?api-version=2023-07-01")
            if not vm_details:
                return
            
            # Get network interfaces
            network_interfaces = []
            for nic_ref in vm_details.get('properties', {}).get('networkProfile', {}).get('networkInterfaces', []):
                nic_id = nic_ref['id']
                nic_details = self.make_request(f"{nic_id}?api-version=2023-07-01")
                if nic_details:
                    network_interfaces.append(nic_details)
            
            # Get disks
            disks = []
            for disk_ref in vm_details.get('properties', {}).get('storageProfile', {}).get('dataDisks', []):
                disk_id = disk_ref['managedDisk']['id']
                disk_details = self.make_request(f"{disk_id}?api-version=2023-07-01")
                if disk_details:
                    disks.append(disk_details)
            
            # Get extensions
            extensions = []
            extensions_url = f"{vm_id}/extensions?api-version=2023-07-01"
            extensions_list = self.make_request(extensions_url)
            if extensions_list and 'value' in extensions_list:
                for ext in extensions_list['value']:
                    ext_id = ext['id']
                    ext_details = self.make_request(f"{ext_id}?api-version=2023-07-01")
                    if ext_details:
                        extensions.append(ext_details)
            
            # Combine all configuration data
            config_data = {
                'vm_details': vm_details,
                'network_interfaces': network_interfaces,
                'disks': disks,
                'extensions': extensions
            }
            
            # Save the configuration
            self.save_configuration(
                source='azure',
                resource_type='virtual_machine',
                resource_id=vm_id,
                resource_name=vm_name,
                config_data=config_data
            )
            
        except Exception as e:
            logger.exception(f"Error polling VM details: {str(e)}") 