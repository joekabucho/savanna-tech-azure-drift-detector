"""
Network Security Group poller module for Azure.

This module provides functionality for polling Azure Network Security Group configurations.
"""

import logging
from .base import BasePoller

logger = logging.getLogger(__name__)

class NSGPoller(BasePoller):
    """
    Poller for Azure Network Security Group resources.
    
    This class handles polling of NSG configurations including:
    - NSG properties and settings
    - Security rules (inbound and outbound)
    - Associated subnets
    - Network interfaces
    """
    
    def poll(self):
        """
        Poll all NSGs in the subscription.
        
        Returns:
            bool: True if polling was successful, False otherwise
        """
        try:
            # Get all NSGs in the subscription
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-04-01"
            nsgs = self.make_request(url)
            
            if not nsgs or 'value' not in nsgs:
                logger.warning("No NSGs found or invalid response")
                return False
            
            for nsg in nsgs['value']:
                self._poll_nsg_details(nsg)
            
            return True
            
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
            nsg_details = self.make_request(f"{nsg_id}?api-version=2023-04-01")
            if not nsg_details:
                return
            
            # Get security rules
            security_rules = {
                'inbound': [],
                'outbound': []
            }
            
            # Process inbound rules
            for rule in nsg_details.get('properties', {}).get('securityRules', []):
                if rule.get('properties', {}).get('direction') == 'Inbound':
                    security_rules['inbound'].append(rule)
                else:
                    security_rules['outbound'].append(rule)
            
            # Get associated subnets
            subnets = []
            for subnet in nsg_details.get('properties', {}).get('subnets', []):
                subnet_id = subnet['id']
                subnet_details = self.make_request(f"{subnet_id}?api-version=2023-04-01")
                if subnet_details:
                    subnets.append(subnet_details)
            
            # Get associated network interfaces
            network_interfaces = []
            for nic in nsg_details.get('properties', {}).get('networkInterfaces', []):
                nic_id = nic['id']
                nic_details = self.make_request(f"{nic_id}?api-version=2023-04-01")
                if nic_details:
                    network_interfaces.append(nic_details)
            
            # Combine all configuration data
            config_data = {
                'nsg_details': nsg_details,
                'security_rules': security_rules,
                'subnets': subnets,
                'network_interfaces': network_interfaces
            }
            
            # Save the configuration
            self.save_configuration(
                source='azure',
                resource_type='network_security_group',
                resource_id=nsg_id,
                resource_name=nsg_name,
                config_data=config_data
            )
            
        except Exception as e:
            logger.exception(f"Error polling NSG details: {str(e)}") 