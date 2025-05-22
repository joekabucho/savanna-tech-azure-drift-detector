"""
Storage Account poller module for Azure.

This module provides functionality for polling Azure Storage Account configurations.
"""

import logging
import requests
from datetime import datetime
from ..azure_poller import save_configuration

logger = logging.getLogger(__name__)

class StoragePoller:
    """
    Poller for Azure Storage Account resources.
    
    This class handles polling of storage account configurations including:
    - Account properties and settings
    - Blob containers
    - File shares
    - Access policies
    - Network rules
    """
    
    def __init__(self, access_token):
        """
        Initialize Storage poller.
        
        Args:
            access_token (str): Azure access token
        """
        self.access_token = access_token
        self.subscription_id = None
        
    def poll(self):
        """Poll Storage Account configurations for the current subscription."""
        if not self.subscription_id:
            logger.error("Subscription ID not set")
            return
            
        try:
            # Get list of storage accounts
            storage_accounts = self._get_storage_account_list()
            
            # Poll each storage account
            for account in storage_accounts:
                account_id = account['id']
                account_name = account['name']
                account_config = self._get_storage_account_config(account_id)
                
                if account_config:
                    # Save configuration
                    save_configuration(
                        source='azure',
                        resource_type='storage_account',
                        resource_id=account_id,
                        resource_name=account_name,
                        config_data=account_config
                    )
                    
        except Exception as e:
            logger.exception(f"Error polling storage accounts: {str(e)}")
            
    def _get_storage_account_list(self):
        """
        Get list of storage accounts in the subscription.
        
        Returns:
            list: List of storage account objects
        """
        try:
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2021-08-01"
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
            
    def _get_storage_account_config(self, account_id):
        """
        Get detailed configuration for a storage account.
        
        Args:
            account_id (str): Storage account resource ID
            
        Returns:
            dict: Storage account configuration or None if request fails
        """
        try:
            url = f"https://management.azure.com{account_id}?api-version=2021-08-01"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get storage account config for {account_id}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.exception(f"Error getting storage account config: {str(e)}")
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