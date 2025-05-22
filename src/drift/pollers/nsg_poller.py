"""
Network Security Group poller module for Azure.

This module provides functionality for polling Azure Network Security Group configurations.
"""

import logging
import requests
from datetime import datetime
from ..azure_poller import save_configuration

logger = logging.getLogger(__name__)

class NSGPoller:
    """
    Poller for Azure Network Security Group resources.
    
    This class handles polling of NSG configurations including:
    - NSG properties and settings
    - Security rules (inbound and outbound)
    - Associated subnets
    - Network interfaces
    """
    
    def __init__(self, access_token):
        """
        Initialize NSG poller.
        
        Args:
            access_token (str): Azure access token
        """
        self.access_token = access_token
        self.subscription_id = None
        
    def poll(self):
        """
        Poll all NSGs in the subscription.
        
        Returns:
            bool: True if polling was successful, False otherwise
        """
        if not self.subscription_id:
            logger.error("Subscription ID not set")
            return False
            
        try:
            # Get all NSGs in the subscription
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2021-08-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                nsgs = response.json().get('value', [])
                
                if not nsgs:
                    logger.warning("No NSGs found or invalid response")
                    return False
                
                for nsg in nsgs:
                    self._poll_nsg_details(nsg)
                
                return True
            else:
                logger.warning(f"Failed to get NSG list: {response.status_code}")
                return False
            
        except Exception as e:
            logger.exception(f"Error polling NSGs: {str(e)}")
            return False
    
    def _poll_nsg_details(self, nsg):
        """
        Poll detailed configuration for a specific NSG.
        
        Args:
            nsg (dict): Basic NSG information from list call
        """
        try:
            nsg_id = nsg['id']
            nsg_name = nsg['name']
            
            # Get detailed NSG configuration
            nsg_config = self._get_nsg_config(nsg_id)
            if not nsg_config:
                return
            
            # Get security rules
            security_rules = {
                'inbound': [],
                'outbound': []
            }
            
            # Process inbound rules
            for rule in nsg_config.get('properties', {}).get('securityRules', []):
                if rule.get('properties', {}).get('direction') == 'Inbound':
                    security_rules['inbound'].append(rule)
                else:
                    security_rules['outbound'].append(rule)
            
            # Get associated subnets
            subnets = []
            for subnet in nsg_config.get('properties', {}).get('subnets', []):
                subnet_id = subnet['id']
                subnet_details = self._get_nsg_config(subnet_id)
                if subnet_details:
                    subnets.append(subnet_details)
            
            # Get associated network interfaces
            network_interfaces = []
            for nic in nsg_config.get('properties', {}).get('networkInterfaces', []):
                nic_id = nic['id']
                nic_details = self._get_nsg_config(nic_id)
                if nic_details:
                    network_interfaces.append(nic_details)
            
            # Combine all configuration data
            config_data = {
                'nsg_details': nsg_config,
                'security_rules': security_rules,
                'subnets': subnets,
                'network_interfaces': network_interfaces
            }
            
            # Save the configuration
            save_configuration(
                source='azure',
                resource_type='network_security_group',
                resource_id=nsg_id,
                resource_name=nsg_name,
                config_data=config_data
            )
            
        except Exception as e:
            logger.exception(f"Error polling NSG details: {str(e)}")
    
    def _get_nsg_config(self, nsg_id):
        """
        Get detailed configuration for an NSG.
        
        Args:
            nsg_id (str): NSG resource ID
            
        Returns:
            dict: NSG configuration or None if request fails
        """
        try:
            url = f"https://management.azure.com{nsg_id}?api-version=2021-08-01"
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
            logger.exception(f"Error getting NSG config: {str(e)}")
            return None 