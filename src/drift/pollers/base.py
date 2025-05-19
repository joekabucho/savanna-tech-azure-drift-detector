"""
Base poller module for Azure resource polling.

This module provides the base class and common functionality for all Azure resource pollers.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from src.core.app import db
from src.core.models import Configuration

logger = logging.getLogger(__name__)

class BasePoller(ABC):
    """
    Base class for all Azure resource pollers.
    
    This class provides common functionality for polling Azure resources
    and saving their configurations.
    """
    
    def __init__(self, access_token, subscription_id=None):
        """
        Initialize the poller.
        
        Args:
            access_token (str): Azure access token for API calls
            subscription_id (str, optional): Azure subscription ID
        """
        self.access_token = access_token
        self.subscription_id = subscription_id
        self.headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
    
    @abstractmethod
    def poll(self):
        """
        Poll the Azure resource.
        
        This method must be implemented by subclasses to poll specific
        Azure resources and save their configurations.
        """
        pass
    
    def save_configuration(self, source, resource_type, resource_id, resource_name, config_data):
        """
        Save or update a resource configuration.
        
        Args:
            source (str): Source of the configuration (e.g., 'azure')
            resource_type (str): Type of resource
            resource_id (str): Unique identifier for the resource
            resource_name (str): Display name of the resource
            config_data (dict): Configuration data to store
        """
        try:
            config = Configuration.query.filter_by(
                source=source,
                resource_type=resource_type,
                resource_id=resource_id
            ).first()
            
            if config:
                if config.config_data != config_data:
                    config.config_data = config_data
                    config.last_updated = datetime.utcnow()
                    db.session.commit()
            else:
                new_config = Configuration(
                    source=source,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    resource_name=resource_name,
                    config_data=config_data
                )
                db.session.add(new_config)
                db.session.commit()
                
        except Exception as e:
            logger.exception(f"Error saving configuration: {str(e)}")
            db.session.rollback()
    
    def make_request(self, url, method='GET', data=None):
        """
        Make an HTTP request to the Azure API.
        
        Args:
            url (str): API endpoint URL
            method (str): HTTP method (GET, POST, etc.)
            data (dict, optional): Request body data
            
        Returns:
            dict: Response data or None if request failed
        """
        try:
            import requests
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=data
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"API request failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.exception(f"Error making API request: {str(e)}")
            return None 