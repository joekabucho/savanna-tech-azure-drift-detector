"""
Dashboard routes for the Azure Drift Detector application.

This module handles the dashboard view and related statistics.
"""

import logging
from datetime import datetime, timedelta
from flask import render_template
from flask_login import login_required

from src.core.app import app
from src.core.models import Configuration, ConfigurationHistory, SigningLog

logger = logging.getLogger(__name__)

def get_dashboard_stats():
    """
    Get statistics for the dashboard.
    
    Returns:
        dict: Dictionary containing dashboard statistics:
            - total_resources: Total number of monitored resources
            - critical_changes: Number of critical configuration changes
            - recent_changes: Number of changes in the last 24 hours
            - signin_events: Number of sign-in events in the last 24 hours
    """
    total_resources = Configuration.query.count()
    critical_changes = ConfigurationHistory.query.filter_by(severity='critical').count()
    
    # Get recent changes (last 24 hours)
    one_day_ago = datetime.utcnow() - timedelta(days=1)
    recent_changes = ConfigurationHistory.query.filter(
        ConfigurationHistory.changed_at >= one_day_ago
    ).count()
    
    # Get sign-in events (last 24 hours)
    signin_events = SigningLog.query.filter(
        SigningLog.timestamp >= one_day_ago
    ).count()
    
    return {
        'total_resources': total_resources,
        'critical_changes': critical_changes,
        'recent_changes': recent_changes,
        'signin_events': signin_events
    }

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Dashboard route handler.
    
    Displays overview of Azure resource monitoring statistics.
    Requires user authentication.
    """
    stats = get_dashboard_stats()
    return render_template('dashboard.html', 
                          total_resources=stats['total_resources'],
                          critical_changes=stats['critical_changes'],
                          recent_changes=stats['recent_changes'],
                          signin_events=stats['signin_events']) 