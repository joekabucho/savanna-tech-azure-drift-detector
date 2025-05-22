"""
MongoDB operations module.

This module provides functions for MongoDB operations used across the application.
"""

import logging
from datetime import datetime
from .mongodb import get_collection

logger = logging.getLogger(__name__)

def save_configuration(source, resource_type, resource_id, resource_name, config_data):
    """
    Save resource configuration to MongoDB.
    
    Args:
        source (str): Source of the configuration (e.g., 'azure', 'm365')
        resource_type (str): Type of resource
        resource_id (str): Resource identifier
        resource_name (str): Resource name
        config_data (dict): Configuration data
    """
    try:
        configs_collection = get_collection('configurations')
        
        # Create configuration document
        config_doc = {
            'source': source,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'resource_name': resource_name,
            'config_data': config_data,
            'timestamp': datetime.utcnow()
        }
        
        # Insert into MongoDB
        configs_collection.insert_one(config_doc)
        logger.debug(f"Saved configuration for {resource_type} {resource_id}")
        
    except Exception as e:
        logger.error(f"Error saving configuration: {str(e)}")
        raise

def save_signin_log(log_data):
    """
    Save a sign-in log entry to MongoDB.
    
    Args:
        log_data (dict): Log entry data containing timestamp, user info, etc.
    """
    try:
        logs_collection = get_collection('signin_logs')
        logs_collection.insert_one(log_data)
        logger.debug(f"Saved sign-in log for user {log_data.get('user_principal_name')}")
        
    except Exception as e:
        logger.error(f"Error saving sign-in log: {str(e)}")
        raise

def save_drift_history(drift_data):
    """
    Save drift detection results to MongoDB.
    
    Args:
        drift_data (dict): Drift detection data containing resource info, changes, etc.
    """
    try:
        drift_collection = get_collection('drift_history')
        drift_collection.insert_one(drift_data)
        logger.debug(f"Saved drift history for resource {drift_data.get('resource_id')}")
        
    except Exception as e:
        logger.error(f"Error saving drift history: {str(e)}")
        raise 