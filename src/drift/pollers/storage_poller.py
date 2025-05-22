"""
Storage Account poller module.

This module handles polling of Azure Storage Account configurations.
"""

import logging
import requests
from datetime import datetime
from src.core.mongodb_ops import save_configuration

logger = logging.getLogger(__name__)

class StoragePoller:
    """Poller for Azure Storage Account configurations."""
    
    def __init__(self, access_token):
        """
        Initialize the storage poller.
        
        Args:
            access_token (str): Azure access token
        """
        self.access_token = access_token
        self.subscription_id = None
    
    def poll(self):
        """
        Poll storage account configurations.
        
        This method retrieves the list of storage accounts in the subscription and
        polls the configuration for each account.
        """
        if not self.subscription_id:
            logger.error("No subscription ID set")
            return
        
        try:
            # Get list of storage accounts
            storage_list = self._get_storage_account_list()
            if not storage_list:
                return
            
            # Poll each storage account
            for storage in storage_list:
                storage_id = storage['id']
                storage_name = storage['name']
                storage_config = self._get_storage_account_config(storage_id)
                
                if storage_config:
                    # Save storage account configuration
                    save_configuration(
                        'azure',
                        'storage_account',
                        storage_id,
                        storage_name,
                        storage_config
                    )
                    
        except Exception as e:
            logger.exception(f"Error polling storage account configurations: {str(e)}")
    
    def _get_storage_account_list(self):
        """
        Get list of storage accounts in the subscription.
        
        Returns:
            list: List of storage account objects or empty list if request fails
        """
        try:
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2021-04-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json().get('value', [])
            else:
                logger.warning(f"Failed to get storage account list: {response.status_code}")
                return []
                
        except Exception as e:
            logger.exception(f"Error getting storage account list: {str(e)}")
            return []
    
    def _get_storage_account_config(self, storage_id):
        """
        Get detailed configuration for a storage account.
        
        Args:
            storage_id (str): Storage account resource ID
            
        Returns:
            dict: Storage account configuration or None if request fails
        """
        try:
            url = f"https://management.azure.com{storage_id}?api-version=2021-04-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get storage account config for {storage_id}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.exception(f"Error getting storage account config for {storage_id}: {str(e)}")
            return None
    
    def _poll_storage_details(self, account):
        """
        Poll detailed configuration for a specific storage account.
        
        Args:
            account (dict): Basic storage account information from list call
        """
        try:
            account_id = account['id']
            account_name = account['name']
            
            # Get detailed storage account configuration
            account_details = self._get_storage_account_config(account_id)
            if not account_details:
                return
            
            # Get blob containers
            containers = []
            containers_url = f"{account_id}/blobServices/default/containers?api-version=2023-01-01"
            containers_list = self.make_request(containers_url)
            if containers_list and 'value' in containers_list:
                for container in containers_list['value']:
                    container_id = container['id']
                    container_details = self.make_request(f"{container_id}?api-version=2023-01-01")
                    if container_details:
                        containers.append(container_details)
            
            # Get file shares
            shares = []
            shares_url = f"{account_id}/fileServices/default/shares?api-version=2023-01-01"
            shares_list = self.make_request(shares_url)
            if shares_list and 'value' in shares_list:
                for share in shares_list['value']:
                    share_id = share['id']
                    share_details = self.make_request(f"{share_id}?api-version=2023-01-01")
                    if share_details:
                        shares.append(share_details)
            
            # Get access policies
            access_policies = []
            policies_url = f"{account_id}/blobServices/default/containers?api-version=2023-01-01"
            policies_list = self.make_request(policies_url)
            if policies_list and 'value' in policies_list:
                for policy in policies_list['value']:
                    if 'properties' in policy and 'publicAccess' in policy['properties']:
                        access_policies.append(policy)
            
            # Get network rules
            network_rules = account_details.get('properties', {}).get('networkAcls', {})
            
            # Combine all configuration data
            config_data = {
                'account_details': account_details,
                'containers': containers,
                'shares': shares,
                'access_policies': access_policies,
                'network_rules': network_rules
            }
            
            # Save the configuration
            save_configuration(
                source='azure',
                resource_type='storage_account',
                resource_id=account_id,
                resource_name=account_name,
                config_data=config_data
            )
            
        except Exception as e:
            logger.exception(f"Error polling storage account details: {str(e)}") 