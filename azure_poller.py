from dotenv import load_dotenv
import os
import json
import logging
from datetime import datetime, timedelta
import requests
from msal import ConfidentialClientApplication

from app import app, db
from models import Configuration, ConfigurationHistory, SigningLog
from drift_detector import detect_drift

logger = logging.getLogger(__name__)
load_dotenv()

GRAPH_API_ENDPOINT = 'https://graph.microsoft.com/v1.0'
AZURE_API_ENDPOINT = 'https://management.azure.com'
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET  = os.environ.get("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID  = os.environ.get("AZURE_TENANT_ID") 

def get_azure_token():
    if not all([AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID]):
        logger.error("Azure credentials not properly configured")
        return None
    
    app = ConfidentialClientApplication(
        AZURE_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{AZURE_TENANT_ID}",
        client_credential=AZURE_CLIENT_SECRET
    )
    
    graph_result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    azure_result = app.acquire_token_for_client(scopes=["https://management.azure.com/.default"])
    
    return {
        'graph': graph_result.get('access_token') if 'access_token' in graph_result else None,
        'azure': azure_result.get('access_token') if 'access_token' in azure_result else None
    }

def poll_azure_configurations():
    logger.info("Starting Azure configuration polling")
    
    tokens = get_azure_token()
    if not tokens or not tokens['graph'] or not tokens['azure']:
        logger.error("Failed to obtain Azure access tokens")
        return
    
    with app.app_context():
        try:
            poll_m365_configurations(tokens['graph'])
            poll_azure_resources(tokens['azure'])
            poll_entra_signing_logs(tokens['graph'])
            logger.info("Azure configuration polling completed successfully")
        except Exception as e:
            logger.exception(f"Error during Azure configuration polling: {str(e)}")

def poll_m365_configurations(access_token):
    logger.info("Polling Microsoft 365 configurations")
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.get(
            f"{GRAPH_API_ENDPOINT}/admin/sharepoint/settings",
            headers=headers
        )
        if response.status_code == 200:
            save_configuration('microsoft365', 'SharePoint', 'settings', 'SharePoint Settings', response.json())
        else:
            logger.warning(f"Failed to get SharePoint settings: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception(f"Error polling SharePoint settings: {str(e)}")
    
    try:
        response = requests.get(
            f"{GRAPH_API_ENDPOINT}/admin/exchange/settings",
            headers=headers
        )
        if response.status_code == 200:
            save_configuration('microsoft365', 'Exchange', 'settings', 'Exchange Settings', response.json())
        else:
            logger.warning(f"Failed to get Exchange settings: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception(f"Error polling Exchange settings: {str(e)}")
    
    try:
        response = requests.get(
            f"{GRAPH_API_ENDPOINT}/admin/teams/settings",
            headers=headers
        )
        if response.status_code == 200:
            save_configuration('microsoft365', 'Teams', 'settings', 'Teams Settings', response.json())
        else:
            logger.warning(f"Failed to get Teams settings: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception(f"Error polling Teams settings: {str(e)}")

def poll_azure_resources(access_token):
    logger.info("Polling Azure resources")
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.get(
            f"{AZURE_API_ENDPOINT}/subscriptions?api-version=2020-01-01",
            headers=headers
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to get Azure subscriptions: {response.status_code} - {response.text}")
            return
        
        subscriptions = response.json().get('value', [])
        
        for subscription in subscriptions:
            subscription_id = subscription['subscriptionId']
            poll_azure_virtual_machines(headers, subscription_id)
            poll_azure_storage_accounts(headers, subscription_id)
            poll_azure_network_security_groups(headers, subscription_id)
            poll_azure_key_vaults(headers, subscription_id)
            
    except Exception as e:
        logger.exception(f"Error polling Azure resources: {str(e)}")

def poll_azure_virtual_machines(headers, subscription_id):
    try:
        response = requests.get(
            f"{AZURE_API_ENDPOINT}/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2021-03-01",
            headers=headers
        )
        
        if response.status_code == 200:
            vms = response.json().get('value', [])
            for vm in vms:
                vm_id = vm['id']
                vm_name = vm['name']
                save_configuration('azure', 'VirtualMachine', vm_id, vm_name, vm)
        else:
            logger.warning(f"Failed to get virtual machines: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception(f"Error polling Azure virtual machines: {str(e)}")

def poll_azure_storage_accounts(headers, subscription_id):
    try:
        response = requests.get(
            f"{AZURE_API_ENDPOINT}/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2021-04-01",
            headers=headers
        )
        
        if response.status_code == 200:
            storage_accounts = response.json().get('value', [])
            for account in storage_accounts:
                account_id = account['id']
                account_name = account['name']
                save_configuration('azure', 'StorageAccount', account_id, account_name, account)
        else:
            logger.warning(f"Failed to get storage accounts: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception(f"Error polling Azure storage accounts: {str(e)}")

def poll_azure_network_security_groups(headers, subscription_id):
    try:
        response = requests.get(
            f"{AZURE_API_ENDPOINT}/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2021-02-01",
            headers=headers
        )
        
        if response.status_code == 200:
            nsgs = response.json().get('value', [])
            for nsg in nsgs:
                nsg_id = nsg['id']
                nsg_name = nsg['name']
                save_configuration('azure', 'NetworkSecurityGroup', nsg_id, nsg_name, nsg)
        else:
            logger.warning(f"Failed to get network security groups: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception(f"Error polling Azure network security groups: {str(e)}")

def poll_azure_key_vaults(headers, subscription_id):
    try:
        response = requests.get(
            f"{AZURE_API_ENDPOINT}/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2021-06-01-preview",
            headers=headers
        )
        
        if response.status_code == 200:
            vaults = response.json().get('value', [])
            for vault in vaults:
                vault_id = vault['id']
                vault_name = vault['name']
                save_configuration('azure', 'KeyVault', vault_id, vault_name, vault)
        else:
            logger.warning(f"Failed to get key vaults: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception(f"Error polling Azure key vaults: {str(e)}")

def poll_entra_signing_logs(access_token):
    logger.info("Polling Entra ID signing logs")
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    start_time = (datetime.utcnow() - timedelta(days=1)).isoformat() + 'Z'
    
    try:
        response = requests.get(
            f"{GRAPH_API_ENDPOINT}/auditLogs/signIns?$filter=createdDateTime ge {start_time}&$top=50",
            headers=headers
        )
        
        if response.status_code == 200:
            logs = response.json().get('value', [])
            ingest_signing_logs(logs)
        else:
            logger.warning(f"Failed to get signing logs: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception(f"Error polling Entra signing logs: {str(e)}")

def ingest_signing_logs(logs):
    try:
        for log in logs:
            sign_log = SigningLog(
                user_id=log.get('userId'),
                app_id=log.get('appId'),
                ip_address=log.get('ipAddress'),
                location=json.dumps(log.get('location')),
                status=json.dumps(log.get('status')),
                timestamp=datetime.strptime(log.get('createdDateTime'), "%Y-%m-%dT%H:%M:%S.%fZ")
            )
            db.session.add(sign_log)
        db.session.commit()
    except Exception as e:
        logger.exception(f"Error ingesting signing logs: {str(e)}")
        db.session.rollback()

def save_configuration(source, resource_type, resource_id, resource_name, config_data):
    try:
        config = Configuration.query.filter_by(
            source=source,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        
        config_json = json.dumps(config_data)
        
        if config:
            if config.configuration != config_json:
                drift_detected, changes, severity = detect_drift(config.configuration, config_json)
                
                if drift_detected:
                    history = ConfigurationHistory(
                        configuration_id=config.id,
                        previous_configuration=config.configuration,
                        changes=json.dumps(changes),
                        severity=severity
                    )
                    db.session.add(history)
                
                config.configuration = config_json
                config.last_updated = datetime.utcnow()
                db.session.commit()
        else:
            new_config = Configuration(
                source=source,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_name=resource_name,
                configuration=config_json
            )
            db.session.add(new_config)
            db.session.commit()
            
    except Exception as e:
        logger.exception(f"Error saving configuration: {str(e)}")
        db.session.rollback()
