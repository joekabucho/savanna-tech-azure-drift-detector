"""
Celery configuration for the Azure Drift Detector application.

This module configures Celery for handling asynchronous tasks,
particularly for Azure resource polling and drift detection.
"""

import os
from celery import Celery
from celery.schedules import crontab

# Initialize Celery
celery_app = Celery('azure_drift_detector')

# Configure Celery
celery_app.conf.update(
    # Broker settings
    broker_url=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    result_backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
    
    # Task settings
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Worker settings
    worker_prefetch_multiplier=1,  # Process one task at a time
    worker_max_tasks_per_child=1000,  # Restart worker after 1000 tasks
    worker_max_memory_per_child=200000,  # Restart worker after 200MB memory usage
    
    # Beat settings for periodic tasks
    beat_schedule={
        'poll-azure-resources': {
            'task': 'src.drift.tasks.poll_azure_resources',
            'schedule': crontab(minute=f"*/{os.environ.get('POLLING_INTERVAL', '30')}"),
            'options': {'queue': 'polling'}
        },
        'poll-entra-logs': {
            'task': 'src.drift.tasks.poll_entra_logs',
            'schedule': crontab(minute='*/15'),  # Every 15 minutes
            'options': {'queue': 'polling'}
        }
    }
)

# Optional: Configure task routing
celery_app.conf.task_routes = {
    'src.drift.tasks.poll_azure_resources': {'queue': 'polling'},
    'src.drift.tasks.poll_entra_logs': {'queue': 'polling'},
    'src.drift.tasks.detect_drift': {'queue': 'analysis'}
} 