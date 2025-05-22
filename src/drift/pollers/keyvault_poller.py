"""
Key Vault poller module.

This module handles polling of Azure Key Vault configurations.
"""

import logging
import requests
from datetime import datetime
from src.core.mongodb_ops import save_configuration

logger = logging.getLogger(__name__)

class KeyVaultPoller:
    """Poller for Azure Key Vault configurations."""
    
    def __init__(self, access_token):
        """
        Initialize the Key Vault poller.
        
        Args:
            access_token (str): Azure access token
        """
        self.access_token = access_token
        self.subscription_id = None
    
    def poll(self):
        """
        Poll Key Vault configurations.
        
        This method retrieves the list of Key Vaults in the subscription and
        polls the configuration for each vault.
        """
        if not self.subscription_id:
            logger.error("No subscription ID set")
            return
        
        try:
            # Get list of Key Vaults
            vault_list = self._get_vault_list()
            if not vault_list:
                return
            
            # Poll each Key Vault
            for vault in vault_list:
                vault_id = vault['id']
                vault_name = vault['name']
                vault_config = self._get_vault_config(vault_id)
                
                if vault_config:
                    # Save Key Vault configuration
                    save_configuration(
                        'azure',
                        'key_vault',
                        vault_id,
                        vault_name,
                        vault_config
                    )
                    
        except Exception as e:
            logger.exception(f"Error polling Key Vault configurations: {str(e)}")
    
    def _get_vault_list(self):
        """
        Get list of Key Vaults in the subscription.
        
        Returns:
            list: List of Key Vault objects or empty list if request fails
        """
        try:
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2021-04-01"
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
    
    def _get_vault_config(self, vault_id):
        """
        Get detailed configuration for a Key Vault.
        
        Args:
            vault_id (str): Key Vault resource ID
            
        Returns:
            dict: Key Vault configuration or None if request fails
        """
        try:
            url = f"https://management.azure.com{vault_id}?api-version=2021-04-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get Key Vault config for {vault_id}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.exception(f"Error getting Key Vault config for {vault_id}: {str(e)}")
            return None 