"""
Azure resource polling module.

This module orchestrates the polling of Azure resource configurations for drift detection.
It uses the Microsoft Authentication Library (MSAL) to acquire tokens and then
delegates the actual polling to specialized poller classes for each resource type.
"""

import logging
import msal
from datetime import datetime, timedelta
from .pollers import VMPoller, StoragePoller, NSGPoller, KeyVaultPoller

logger = logging.getLogger(__name__)

def get_azure_token():
    """
    Get access tokens for Azure and Microsoft Graph APIs.
    
    Returns:
        tuple: (azure_token, graph_token) or (None, None) if token acquisition fails
    """
    try:
        # Initialize MSAL app
        app = msal.ConfidentialClientApplication(
            client_id="YOUR_CLIENT_ID",
            client_credential="YOUR_CLIENT_SECRET",
            authority="https://login.microsoftonline.com/YOUR_TENANT_ID"
        )
        
        # Get Azure token
        azure_token = app.acquire_token_for_client(
            scopes=["https://management.azure.com/.default"]
        )
        
        # Get Graph token
        graph_token = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        
        if 'access_token' in azure_token and 'access_token' in graph_token:
            return azure_token['access_token'], graph_token['access_token']
        else:
            logger.error("Failed to acquire tokens")
            return None, None
            
    except Exception as e:
        logger.exception(f"Error acquiring tokens: {str(e)}")
        return None, None

def poll_azure_configurations():
    """
    Poll Azure and Microsoft 365 configurations.
    
    This function orchestrates the polling of various Azure resources and
    Microsoft 365 services. It first acquires the necessary tokens and then
    delegates the polling to specialized poller classes.
    
    Returns:
        bool: True if polling was successful, False otherwise
    """
    try:
        # Get access tokens
        azure_token, graph_token = get_azure_token()
        if not azure_token or not graph_token:
            return False
        
        # Get list of subscriptions
        subscriptions = get_subscriptions(azure_token)
        if not subscriptions:
            return False
        
        # Initialize pollers
        pollers = [
            VMPoller(azure_token),
            StoragePoller(azure_token),
            NSGPoller(azure_token),
            KeyVaultPoller(azure_token)
        ]
        
        # Poll each subscription
        for subscription in subscriptions:
            subscription_id = subscription['subscriptionId']
            logger.info(f"Polling subscription: {subscription_id}")
            
            # Update pollers with current subscription
            for poller in pollers:
                poller.subscription_id = subscription_id
                poller.poll()
        
        # Poll Microsoft 365 configurations
        poll_m365_configurations(graph_token)
        
        return True
        
    except Exception as e:
        logger.exception(f"Error polling configurations: {str(e)}")
        return False

def get_subscriptions(access_token):
    """
    Get list of Azure subscriptions.
    
    Args:
        access_token (str): Azure access token
        
    Returns:
        list: List of subscription objects or empty list if request fails
    """
    try:
        import requests
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(
            'https://management.azure.com/subscriptions?api-version=2020-01-01',
            headers=headers
        )
        
        if response.status_code == 200:
            return response.json().get('value', [])
        else:
            logger.warning(f"Failed to get subscriptions: {response.status_code}")
            return []
            
    except Exception as e:
        logger.exception(f"Error getting subscriptions: {str(e)}")
        return []

def poll_m365_configurations(access_token):
    """
    Poll Microsoft 365 service configurations.
    
    This function polls configurations from various Microsoft 365 services
    including SharePoint, Exchange, and Teams.
    
    Args:
        access_token (str): Microsoft Graph access token
    """
    try:
        import requests
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        # Poll SharePoint settings
        sharepoint_url = 'https://graph.microsoft.com/v1.0/sites/root'
        sharepoint_response = requests.get(sharepoint_url, headers=headers)
        if sharepoint_response.status_code == 200:
            sharepoint_config = sharepoint_response.json()
            # Save SharePoint configuration
            save_configuration('m365', 'sharepoint', 'root', 'SharePoint Root', sharepoint_config)
        
        # Poll Exchange settings
        exchange_url = 'https://graph.microsoft.com/v1.0/admin/exchange/settings'
        exchange_response = requests.get(exchange_url, headers=headers)
        if exchange_response.status_code == 200:
            exchange_config = exchange_response.json()
            # Save Exchange configuration
            save_configuration('m365', 'exchange', 'settings', 'Exchange Settings', exchange_config)
        
        # Poll Teams settings
        teams_url = 'https://graph.microsoft.com/v1.0/teams'
        teams_response = requests.get(teams_url, headers=headers)
        if teams_response.status_code == 200:
            teams_config = teams_response.json()
            # Save Teams configuration
            save_configuration('m365', 'teams', 'teams', 'Teams Settings', teams_config)
            
    except Exception as e:
        logger.exception(f"Error polling M365 configurations: {str(e)}")

def poll_entra_signing_logs():
    """
    Poll Entra ID (Azure AD) sign-in logs.
    
    This function retrieves sign-in logs from Azure AD and ingests them
    into the database for analysis.
    """
    try:
        # Get access token
        azure_token, _ = get_azure_token()
        if not azure_token:
            return False
        
        # Calculate time range (last 24 hours)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        # Format times for API
        start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # Get sign-in logs
        url = f"https://management.azure.com/providers/Microsoft.Insights/logs?api-version=2017-04-26"
        query = f"""
        SigninLogs
        | where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
        | project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, Status
        """
        
        headers = {
            'Authorization': f'Bearer {azure_token}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'query': query,
            'timespan': f"{start_time_str}/{end_time_str}"
        }
        
        import requests
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code == 200:
            logs = response.json()
            # Process and store logs
            for log in logs.get('tables', [])[0].get('rows', []):
                save_signin_log(log)
            return True
        else:
            logger.warning(f"Failed to get sign-in logs: {response.status_code}")
            return False
            
    except Exception as e:
        logger.exception(f"Error polling sign-in logs: {str(e)}")
        return False

def save_configuration(source, resource_type, resource_id, resource_name, config_data):
    """
    Save or update a resource configuration.
    
    Args:
        source (str): Source of the configuration (e.g., 'azure', 'm365')
        resource_type (str): Type of resource
        resource_id (str): Unique identifier for the resource
        resource_name (str): Display name of the resource
        config_data (dict): Configuration data to store
    """
    try:
        from src.core.app import db
        from src.core.models import Configuration
        
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

def save_signin_log(log_data):
    """
    Save a sign-in log entry.
    
    Args:
        log_data (list): List containing log entry data
    """
    try:
        from src.core.app import db
        from src.core.models import SignInLog
        
        # Extract data from log entry
        time_generated, user_principal_name, app_display_name, ip_address, location, status = log_data
        
        # Create new log entry
        log = SignInLog(
            timestamp=time_generated,
            user_principal_name=user_principal_name,
            app_display_name=app_display_name,
            ip_address=ip_address,
            location=location,
            status=status
        )
        
        db.session.add(log)
        db.session.commit()
        
    except Exception as e:
        logger.exception(f"Error saving sign-in log: {str(e)}")
        db.session.rollback()
