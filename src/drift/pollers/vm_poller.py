"""
Virtual Machine poller module for Azure.

This module provides functionality for polling Azure Virtual Machine configurations.
"""

import logging
import requests
from datetime import datetime
from ..azure_poller import save_configuration

logger = logging.getLogger(__name__)

class VMPoller:
    """Poller for Azure Virtual Machine configurations."""
    
    def __init__(self, access_token):
        """
        Initialize VM poller.
        
        Args:
            access_token (str): Azure access token
        """
        self.access_token = access_token
        self.subscription_id = None
        
    def poll(self):
        """Poll VM configurations for the current subscription."""
        if not self.subscription_id:
            logger.error("Subscription ID not set")
            return
            
        try:
            # Get list of VMs
            vms = self._get_vm_list()
            
            # Poll each VM
            for vm in vms:
                vm_id = vm['id']
                vm_name = vm['name']
                vm_config = self._get_vm_config(vm_id)
                
                if vm_config:
                    # Save configuration
                    save_configuration(
                        source='azure',
                        resource_type='virtual_machine',
                        resource_id=vm_id,
                        resource_name=vm_name,
                        config_data=vm_config
                    )
                    
        except Exception as e:
            logger.exception(f"Error polling VMs: {str(e)}")
            
    def _get_vm_list(self):
        """
        Get list of VMs in the subscription.
        
        Returns:
            list: List of VM objects
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
            logger.exception(f"Error getting VM config: {str(e)}")
            return None 