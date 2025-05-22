#!/usr/bin/env python
"""
Script to run Celery workers for the Azure Drift Detector application.

This script starts Celery workers for different queues:
- polling: For Azure resource polling tasks
- analysis: For drift detection analysis tasks
"""

import os
import sys
from celery import Celery
from celery.bin.worker import worker

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.celery_app import celery_app

def run_worker(queue_name, concurrency=2):
    """
    Run a Celery worker for a specific queue.
    
    Args:
        queue_name (str): Name of the queue to process
        concurrency (int): Number of worker processes
    """
    worker_instance = worker.Worker(
        app=celery_app,
        queues=[queue_name],
        concurrency=concurrency,
        loglevel='INFO'
    )
    worker_instance.run()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python run_celery.py <queue_name> [concurrency]")
        print("Available queues: polling, analysis")
        sys.exit(1)
    
    queue_name = sys.argv[1]
    concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    
    if queue_name not in ['polling', 'analysis']:
        print(f"Invalid queue name: {queue_name}")
        print("Available queues: polling, analysis")
        sys.exit(1)
    
    print(f"Starting Celery worker for queue: {queue_name}")
    run_worker(queue_name, concurrency) 