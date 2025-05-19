"""
Storage Account poller module for Azure.

This module provides functionality for polling Azure Storage Account configurations.
"""

import logging
from .base import BasePoller

logger = logging.getLogger(__name__)

class StoragePoller(BasePoller):
    """
    Poller for Azure Storage Account resources.
    
    This class handles polling of storage account configurations including:
    - Account properties and settings
    - Blob containers
    - File shares
    - Access policies
    - Network rules
    """
    
    def poll(self):
        """
        Poll all storage accounts in the subscription.
        
        Returns:
            bool: True if polling was successful, False otherwise
        """
        try:
            # Get all storage accounts in the subscription
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
            accounts = self.make_request(url)
            
            if not accounts or 'value' not in accounts:
                logger.warning("No storage accounts found or invalid response")
                return False
            
            for account in accounts['value']:
                self._poll_storage_details(account)
            
            return True
            
        except Exception as e:
            logger.exception(f"Error polling storage accounts: {str(e)}")
            return False
    
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
            account_details = self.make_request(f"{account_id}?api-version=2023-01-01")
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
            self.save_configuration(
                source='azure',
                resource_type='storage_account',
                resource_id=account_id,
                resource_name=account_name,
                config_data=config_data
            )
            
        except Exception as e:
            logger.exception(f"Error polling storage account details: {str(e)}") 