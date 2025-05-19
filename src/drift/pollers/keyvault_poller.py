"""
Key Vault poller module for Azure.

This module provides functionality for polling Azure Key Vault configurations.
"""

import logging
from .base import BasePoller

logger = logging.getLogger(__name__)

class KeyVaultPoller(BasePoller):
    """
    Poller for Azure Key Vault resources.
    
    This class handles polling of Key Vault configurations including:
    - Vault properties and settings
    - Access policies
    - Network rules
    - Diagnostic settings
    """
    
    def poll(self):
        """
        Poll all Key Vaults in the subscription.
        
        Returns:
            bool: True if polling was successful, False otherwise
        """
        try:
            # Get all Key Vaults in the subscription
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01"
            vaults = self.make_request(url)
            
            if not vaults or 'value' not in vaults:
                logger.warning("No Key Vaults found or invalid response")
                return False
            
            for vault in vaults['value']:
                self._poll_vault_details(vault)
            
            return True
            
        except Exception as e:
            logger.exception(f"Error polling Key Vaults: {str(e)}")
            return False
    
    def _poll_vault_details(self, vault):
        """
        Poll detailed configuration for a specific Key Vault.
        
        Args:
            vault (dict): Basic vault information from list call
        """
        try:
            vault_id = vault['id']
            vault_name = vault['name']
            
            # Get detailed vault configuration
            vault_details = self.make_request(f"{vault_id}?api-version=2023-02-01")
            if not vault_details:
                return
            
            # Get access policies
            access_policies = vault_details.get('properties', {}).get('accessPolicies', [])
            
            # Get network rules
            network_rules = vault_details.get('properties', {}).get('networkAcls', {})
            
            # Get diagnostic settings
            diagnostic_settings = []
            diagnostic_url = f"{vault_id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
            diagnostic_list = self.make_request(diagnostic_url)
            if diagnostic_list and 'value' in diagnostic_list:
                for setting in diagnostic_list['value']:
                    diagnostic_settings.append(setting)
            
            # Get private endpoint connections
            private_endpoints = []
            endpoints_url = f"{vault_id}/privateEndpointConnections?api-version=2023-02-01"
            endpoints_list = self.make_request(endpoints_url)
            if endpoints_list and 'value' in endpoints_list:
                for endpoint in endpoints_list['value']:
                    private_endpoints.append(endpoint)
            
            # Combine all configuration data
            config_data = {
                'vault_details': vault_details,
                'access_policies': access_policies,
                'network_rules': network_rules,
                'diagnostic_settings': diagnostic_settings,
                'private_endpoints': private_endpoints
            }
            
            # Save the configuration
            self.save_configuration(
                source='azure',
                resource_type='key_vault',
                resource_id=vault_id,
                resource_name=vault_name,
                config_data=config_data
            )
            
        except Exception as e:
            logger.exception(f"Error polling Key Vault details: {str(e)}") 