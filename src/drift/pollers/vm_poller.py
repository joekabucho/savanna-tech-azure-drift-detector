"""
Virtual Machine poller module.

This module handles polling of Azure Virtual Machine configurations.
"""

import logging
import requests
from datetime import datetime
from src.core.mongodb_ops import save_configuration

logger = logging.getLogger(__name__)

class VMPoller:
    """Poller for Azure Virtual Machine configurations."""
    
    def __init__(self, access_token):
        """
        Initialize the VM poller.
        
        Args:
            access_token (str): Azure access token
        """
        self.access_token = access_token
        self.subscription_id = None
    
    def poll(self):
        """
        Poll VM configurations.
        
        This method retrieves the list of VMs in the subscription and
        polls the configuration for each VM.
        """
        if not self.subscription_id:
            logger.error("No subscription ID set")
            return
        
        try:
            # Get list of VMs
            vm_list = self._get_vm_list()
            if not vm_list:
                return
            
            # Poll each VM
            for vm in vm_list:
                vm_id = vm['id']
                vm_name = vm['name']
                vm_config = self._get_vm_config(vm_id)
                
                if vm_config:
                    # Save VM configuration
                    save_configuration(
                        'azure',
                        'virtual_machine',
                        vm_id,
                        vm_name,
                        vm_config
                    )
                    
        except Exception as e:
            logger.exception(f"Error polling VM configurations: {str(e)}")
    
    def _get_vm_list(self):
        """
        Get list of VMs in the subscription.
        
        Returns:
            list: List of VM objects or empty list if request fails
        """
        try:
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2021-04-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json().get('value', [])
            else:
                logger.warning(f"Failed to get VM list: {response.status_code}")
                return []
                
        except Exception as e:
            logger.exception(f"Error getting VM list: {str(e)}")
            return []
    
    def _get_vm_config(self, vm_id):
        """
        Get detailed configuration for a VM.
        
        Args:
            vm_id (str): VM resource ID
            
        Returns:
            dict: VM configuration or None if request fails
        """
        try:
            url = f"https://management.azure.com{vm_id}?api-version=2021-04-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get VM config for {vm_id}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.exception(f"Error getting VM config for {vm_id}: {str(e)}")
            return None 