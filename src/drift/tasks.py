"""
Celery tasks for Azure resource polling and drift detection.

This module contains Celery tasks for:
- Polling Azure resources
- Polling Entra ID (Azure AD) sign-in logs
- Detecting configuration drift
"""

import logging
from datetime import datetime, timedelta
from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from celery.utils.log import get_task_logger
from bson import ObjectId

from src.core.celery_app import celery_app
from src.drift.azure_poller import poll_azure_configurations, poll_entra_signing_logs
from src.drift.drift_detector import detect_drift
from src.core.mongodb import get_collection
from src.core.models import User, Role, UserRole  # Keep SQLAlchemy models for auth

logger = get_task_logger(__name__)

@shared_task(
    name='src.drift.tasks.poll_azure_resources',
    bind=True,
    max_retries=3,
    default_retry_delay=300,  # 5 minutes
    rate_limit='10/m'  # Maximum 10 tasks per minute
)
def poll_azure_resources(self):
    """
    Poll Azure resources for configuration changes.
    
    This task is responsible for:
    1. Polling all configured Azure resources
    2. Storing current configurations in MongoDB
    3. Detecting drift from previous configurations
    
    Returns:
        dict: Summary of polling results
    """
    try:
        logger.info("Starting Azure resource polling")
        
        # Get MongoDB collections
        configs_collection = get_collection('configurations')
        
        # Poll Azure configurations
        success = poll_azure_configurations()
        
        if not success:
            raise Exception("Failed to poll Azure configurations")
        
        logger.info("Azure resource polling completed successfully")
        return {
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'Azure resource polling completed successfully'
        }
        
    except Exception as e:
        logger.error(f"Error polling Azure resources: {str(e)}")
        try:
            self.retry(exc=e)
        except MaxRetriesExceededError:
            logger.error("Max retries exceeded for Azure resource polling")
            return {
                'status': 'error',
                'timestamp': datetime.utcnow().isoformat(),
                'message': f'Failed to poll Azure resources after max retries: {str(e)}'
            }

@shared_task(
    name='src.drift.tasks.poll_entra_logs',
    bind=True,
    max_retries=3,
    default_retry_delay=300,  # 5 minutes
    rate_limit='4/h'  # Maximum 4 tasks per hour
)
def poll_entra_logs(self):
    """
    Poll Entra ID (Azure AD) sign-in logs.
    
    This task is responsible for:
    1. Polling sign-in logs from Entra ID
    2. Storing logs in MongoDB
    3. Analyzing for suspicious activities
    
    Returns:
        dict: Summary of polling results
    """
    try:
        logger.info("Starting Entra ID sign-in log polling")
        
        # Get MongoDB collection
        logs_collection = get_collection('signin_logs')
        
        # Poll sign-in logs
        success = poll_entra_signing_logs()
        
        if not success:
            raise Exception("Failed to poll Entra ID sign-in logs")
        
        logger.info("Entra ID sign-in log polling completed successfully")
        return {
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'Entra ID sign-in log polling completed successfully'
        }
        
    except Exception as e:
        logger.error(f"Error polling Entra ID sign-in logs: {str(e)}")
        try:
            self.retry(exc=e)
        except MaxRetriesExceededError:
            logger.error("Max retries exceeded for Entra ID sign-in log polling")
            return {
                'status': 'error',
                'timestamp': datetime.utcnow().isoformat(),
                'message': f'Failed to poll Entra ID sign-in logs after max retries: {str(e)}'
            }

@shared_task(
    name='src.drift.tasks.detect_drift',
    bind=True,
    max_retries=2,
    default_retry_delay=600,  # 10 minutes
    rate_limit='1/h'  # Maximum 1 task per hour
)
def detect_drift_task(self, resource_id=None):
    """
    Detect configuration drift for Azure resources.
    
    Args:
        resource_id (str, optional): Specific resource ID to check for drift.
                                    If None, checks all resources.
    
    Returns:
        dict: Summary of drift detection results
    """
    try:
        logger.info(f"Starting drift detection for resource: {resource_id or 'all'}")
        
        # Get MongoDB collections
        configs_collection = get_collection('configurations')
        drift_history_collection = get_collection('drift_history')
        
        # Get configurations to compare
        if resource_id:
            # Get the two most recent configurations for the resource
            configs = list(configs_collection.find(
                {'resource_id': resource_id}
            ).sort('timestamp', -1).limit(2))
        else:
            # Get all resources that have been updated in the last hour
            recent_time = datetime.utcnow() - timedelta(hours=1)
            configs = list(configs_collection.find(
                {'timestamp': {'$gte': recent_time}}
            ).sort('timestamp', -1))
        
        if not configs:
            logger.info("No configurations found for drift detection")
            return {
                'status': 'success',
                'timestamp': datetime.utcnow().isoformat(),
                'message': 'No configurations found for drift detection'
            }
        
        # Detect drift
        drift_results = []
        for i in range(len(configs) - 1):
            current_config = configs[i]
            previous_config = configs[i + 1]
            
            drift_detected, changes, severity = detect_drift(
                previous_config['config_data'],
                current_config['config_data']
            )
            
            if drift_detected:
                # Record drift in history
                drift_record = {
                    'resource_id': current_config['resource_id'],
                    'resource_type': current_config['resource_type'],
                    'previous_config_id': previous_config['_id'],
                    'current_config_id': current_config['_id'],
                    'changes': changes,
                    'severity': severity,
                    'detected_at': datetime.utcnow()
                }
                drift_history_collection.insert_one(drift_record)
                
                drift_results.append({
                    'resource_id': current_config['resource_id'],
                    'resource_type': current_config['resource_type'],
                    'severity': severity,
                    'changes': changes
                })
        
        logger.info(f"Drift detection completed. Found {len(drift_results)} drifts.")
        return {
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'message': f'Drift detection completed. Found {len(drift_results)} drifts.',
            'results': drift_results
        }
        
    except Exception as e:
        logger.error(f"Error detecting drift: {str(e)}")
        try:
            self.retry(exc=e)
        except MaxRetriesExceededError:
            logger.error("Max retries exceeded for drift detection")
            return {
                'status': 'error',
                'timestamp': datetime.utcnow().isoformat(),
                'message': f'Failed to detect drift after max retries: {str(e)}'
            }

@shared_task(name='drift.tasks.detect_drift_for_resource')
def detect_drift_for_resource(resource_id: str, resource_type: str):
    """
    Detect drift for a specific Azure resource.
    
    Args:
        resource_id (str): The Azure resource ID
        resource_type (str): The type of resource (e.g., 'vm', 'storage', 'keyvault')
    """
    try:
        # Get current and previous configurations
        current_config = Configuration.query.filter_by(
            resource_id=resource_id,
            resource_type=resource_type
        ).order_by(Configuration.timestamp.desc()).first()
        
        if not current_config:
            logger.warning(f"No configuration found for resource {resource_id}")
            return None
            
        previous_config = Configuration.query.filter_by(
            resource_id=resource_id,
            resource_type=resource_type
        ).order_by(Configuration.timestamp.desc()).offset(1).first()
        
        if not previous_config:
            logger.info(f"No previous configuration found for resource {resource_id}")
            return None
            
        # Detect drift
        drift_detected, changes, severity = detect_drift(
            previous_config.configuration,
            current_config.configuration
        )
        
        if drift_detected:
            # Record drift in history
            history = ConfigurationHistory(
                resource_id=resource_id,
                resource_type=resource_type,
                previous_config_id=previous_config.id,
                current_config_id=current_config.id,
                changes=changes,
                severity=severity,
                detected_at=datetime.utcnow()
            )
            db.session.add(history)
            db.session.commit()
            
            logger.info(
                f"Drift detected for resource {resource_id}: "
                f"severity={severity}, changes={changes}"
            )
            
            # Trigger notifications based on severity
            if severity in ['critical', 'high']:
                notify_drift.delay(
                    resource_id=resource_id,
                    resource_type=resource_type,
                    severity=severity,
                    changes=changes
                )
                
        return {
            'resource_id': resource_id,
            'drift_detected': drift_detected,
            'severity': severity,
            'changes': changes
        }
        
    except Exception as e:
        logger.exception(f"Error detecting drift for resource {resource_id}: {str(e)}")
        raise

@shared_task(name='drift.tasks.detect_drift_for_all_resources')
def detect_drift_for_all_resources():
    """
    Detect drift for all monitored Azure resources.
    """
    try:
        # Get all unique resource IDs and types
        resources = db.session.query(
            Configuration.resource_id,
            Configuration.resource_type
        ).distinct().all()
        
        for resource_id, resource_type in resources:
            detect_drift_for_resource.delay(resource_id, resource_type)
            
        return {'status': 'success', 'resources_checked': len(resources)}
        
    except Exception as e:
        logger.exception(f"Error in drift detection for all resources: {str(e)}")
        raise

@shared_task(name='drift.tasks.notify_drift')
def notify_drift(resource_id: str, resource_type: str, severity: str, changes: dict):
    """
    Send notifications about detected drift.
    
    Args:
        resource_id (str): The Azure resource ID
        resource_type (str): The type of resource
        severity (str): The severity of the drift
        changes (dict): The detected changes
    """
    try:
        # Get notification settings from PostgreSQL (user preferences)
        # This part still uses PostgreSQL for user data
        from src.core.app import db
        from src.core.models import NotificationSettings
        
        notification_settings = NotificationSettings.query.filter_by(
            user_id=current_user.id
        ).first()
        
        if notification_settings and notification_settings.enabled:
            # TODO: Implement notification logic (email, Slack, etc.)
            logger.info(
                f"Notification for drift in {resource_type} {resource_id}: "
                f"severity={severity}, changes={changes}"
            )
        
    except Exception as e:
        logger.exception(f"Error sending drift notification: {str(e)}")
        raise 