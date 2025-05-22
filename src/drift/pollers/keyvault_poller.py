"""
Key Vault poller module for Azure.

This module provides functionality for polling Azure Key Vault configurations.
"""

import logging
import requests
from datetime import datetime
from ..azure_poller import save_configuration

logger = logging.getLogger(__name__)

class KeyVaultPoller:
    """Poller for Azure Key Vault configurations."""
    
    def __init__(self, access_token):
        """
        Initialize Key Vault poller.
        
        Args:
            access_token (str): Azure access token
        """
        self.access_token = access_token
        self.subscription_id = None
        
    def poll(self):
        """Poll Key Vault configurations for the current subscription."""
        if not self.subscription_id:
            logger.error("Subscription ID not set")
            return
            
        try:
            # Get list of Key Vaults
            keyvaults = self._get_keyvault_list()
            
            # Poll each Key Vault
            for keyvault in keyvaults:
                keyvault_id = keyvault['id']
                keyvault_name = keyvault['name']
                keyvault_config = self._get_keyvault_config(keyvault_id)
                
                if keyvault_config:
                    # Save configuration
                    save_configuration(
                        source='azure',
                        resource_type='key_vault',
                        resource_id=keyvault_id,
                        resource_name=keyvault_name,
                        config_data=keyvault_config
                    )
                    
        except Exception as e:
            logger.exception(f"Error polling Key Vaults: {str(e)}")
            
    def _get_keyvault_list(self):
        """
        Get list of Key Vaults in the subscription.
        
        Returns:
            list: List of Key Vault objects
        """
        try:
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json().get('value', [])
            else:
                logger.warning(f"Failed to get Key Vault list: {response.status_code}")
                return []
                
        except Exception as e:
            logger.exception(f"Error getting Key Vault list: {str(e)}")
            return []
            
    def _get_keyvault_config(self, keyvault_id):
        """
        Get detailed configuration for a Key Vault.
        
        Args:
            keyvault_id (str): Key Vault resource ID
            
        Returns:
            dict: Key Vault configuration or None if request fails
        """
        try:
            url = f"https://management.azure.com{keyvault_id}?api-version=2021-10-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get Key Vault config for {keyvault_id}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.exception(f"Error getting Key Vault config: {str(e)}")
            return None 