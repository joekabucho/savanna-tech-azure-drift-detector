#!/usr/bin/env python
"""
Script to run Celery beat scheduler for the Azure Drift Detector application.

This script starts the Celery beat scheduler to handle periodic tasks:
- Polling Azure resources at configured intervals
- Polling Entra ID sign-in logs every 15 minutes
"""

import os
import sys
from celery import Celery
from celery.bin.beat import beat

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.celery_app import celery_app

def run_beat():
    """
    Run the Celery beat scheduler.
    """
    beat_instance = beat.Beat(
        app=celery_app,
        loglevel='INFO'
    )
    beat_instance.run()

if __name__ == '__main__':
    print("Starting Celery beat scheduler")
    run_beat() 