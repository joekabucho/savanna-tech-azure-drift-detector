"""
Network Security Group poller module.

This module handles polling of Azure Network Security Group configurations.
"""

import logging
import requests
from datetime import datetime
from src.core.mongodb_ops import save_configuration

logger = logging.getLogger(__name__)

class NSGPoller:
    """Poller for Azure Network Security Group configurations."""
    
    def __init__(self, access_token):
        """
        Initialize the NSG poller.
        
        Args:
            access_token (str): Azure access token
        """
        self.access_token = access_token
        self.subscription_id = None
    
    def poll(self):
        """
        Poll NSG configurations.
        
        This method retrieves the list of NSGs in the subscription and
        polls the configuration for each NSG.
        """
        if not self.subscription_id:
            logger.error("No subscription ID set")
            return
        
        try:
            # Get list of NSGs
            nsg_list = self._get_nsg_list()
            if not nsg_list:
                return
            
            # Poll each NSG
            for nsg in nsg_list:
                nsg_id = nsg['id']
                nsg_name = nsg['name']
                nsg_config = self._get_nsg_config(nsg_id)
                
                if nsg_config:
                    # Save NSG configuration
                    save_configuration(
                        'azure',
                        'network_security_group',
                        nsg_id,
                        nsg_name,
                        nsg_config
                    )
                    
        except Exception as e:
            logger.exception(f"Error polling NSG configurations: {str(e)}")
    
    def _get_nsg_list(self):
        """
        Get list of NSGs in the subscription.
        
        Returns:
            list: List of NSG objects or empty list if request fails
        """
        try:
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2021-04-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json().get('value', [])
            else:
                logger.warning(f"Failed to get NSG list: {response.status_code}")
                return []
                
        except Exception as e:
            logger.exception(f"Error getting NSG list: {str(e)}")
            return []
    
    def _get_nsg_config(self, nsg_id):
        """
        Get detailed configuration for an NSG.
        
        Args:
            nsg_id (str): NSG resource ID
            
        Returns:
            dict: NSG configuration or None if request fails
        """
        try:
            url = f"https://management.azure.com{nsg_id}?api-version=2021-04-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get NSG config for {nsg_id}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.exception(f"Error getting NSG config for {nsg_id}: {str(e)}")
            return None 