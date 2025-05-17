"""
Routes module for the Azure Drift Detector application.
Handles all web routes (non-API).
"""

import logging
import os
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    render_template, redirect, url_for, flash, request, 
    session, jsonify, abort, send_file, Response
)
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash

from app import app, db
from models import (
    User, Role, Configuration, ConfigurationHistory, 
    SigningLog, UserRole
)
from utils import (
    format_datetime, format_timeago, format_severity, 
    parse_json_changes, admin_required, operator_required
)

logger = logging.getLogger(__name__)


def get_dashboard_stats():
    """Get statistics for the dashboard"""
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

@app.route('/reports')
@login_required
def reports():
    """Report page for viewing detailed configuration changes"""
    return render_template('reports.html')

@app.route('/settings')
@login_required
def settings():
    """Settings page for application configuration"""
    
    # Only admins and operators can access settings
    if not (current_user.has_role('admin') or current_user.has_role('operator')):
        flash('You do not have permission to access settings', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('settings.html')

@app.route('/users')
@login_required
@admin_required
def users():
    """User management page (admin only)"""
    return render_template('users.html')

@app.route('/export/<report_type>')
@login_required
def export_report(report_type):

    if report_type not in ['changes', 'resources', 'signin']:
        flash('Invalid report type', 'danger')
        return redirect(url_for('reports'))
    
    export_format = request.args.get('format', 'csv')
    if export_format not in ['csv', 'json']:
        flash('Invalid export format', 'danger')
        return redirect(url_for('reports'))
    
    source = request.args.get('source', '')
    resource_type = request.args.get('resourceType', '')
    severity = request.args.get('severity', '')
    date_range = int(request.args.get('dateRange', 7))
    
    # Calculate date range
    start_date = datetime.utcnow() - timedelta(days=date_range)
    
    try:
        if report_type == 'changes':
            if export_format == 'csv':
                return export_changes_csv(start_date, source, resource_type, severity)
            else:
                return export_changes_json(start_date, source, resource_type, severity)
        elif report_type == 'resources':
            if export_format == 'csv':
                return export_resources_csv()
            else:
                return export_resources_json()
        elif report_type == 'signin':
            if export_format == 'csv':
                return export_signin_csv(start_date)
            else:
                return export_signin_json(start_date)
    except Exception as e:
        logger.exception(f"Error exporting report: {str(e)}")
        flash(f'Error exporting report: {str(e)}', 'danger')
        return redirect(url_for('reports'))

def export_changes_csv(start_date, source='', resource_type='', severity=''):
    """Generate CSV export of configuration changes"""
    import csv
    from io import StringIO
    
    query = ConfigurationHistory.query.filter(
        ConfigurationHistory.changed_at >= start_date
    ).join(Configuration)
    
    if source:
        query = query.filter(Configuration.source == source)
    
    if resource_type:
        query = query.filter(Configuration.resource_type == resource_type)
    
    if severity:
        query = query.filter(ConfigurationHistory.severity == severity)
    
    query = query.order_by(ConfigurationHistory.changed_at.desc())
    
    output = StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'ID', 'Resource Name', 'Resource Type', 'Source', 
        'Changed At', 'Severity', 'Changes'
    ])
    
    for history in query.all():
        writer.writerow([
            history.id,
            history.configuration.resource_name,
            history.configuration.resource_type,
            history.configuration.source,
            history.changed_at.strftime('%Y-%m-%d %H:%M:%S'),
            history.severity,
            str(history.changes)
        ])
    
    output.seek(0)
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment;filename=changes_export_{timestamp}.csv'
        }
    )

def export_changes_json(start_date, source='', resource_type='', severity=''):
    """Generate JSON export of configuration changes"""
    import json
    
    query = ConfigurationHistory.query.filter(
        ConfigurationHistory.changed_at >= start_date
    ).join(Configuration)
    
    if source:
        query = query.filter(Configuration.source == source)
    
    if resource_type:
        query = query.filter(Configuration.resource_type == resource_type)
    
    if severity:
        query = query.filter(ConfigurationHistory.severity == severity)
    
    query = query.order_by(ConfigurationHistory.changed_at.desc())
    
    changes = []
    for history in query.all():
        changes.append({
            'id': history.id,
            'resource_name': history.configuration.resource_name,
            'resource_type': history.configuration.resource_type,
            'source': history.configuration.source,
            'changed_at': history.changed_at.strftime('%Y-%m-%d %H:%M:%S'),
            'severity': history.severity,
            'changes': history.changes
        })
    
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return Response(
        json.dumps(changes, indent=2),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment;filename=changes_export_{timestamp}.json'
        }
    )

def export_resources_csv():
    """Generate CSV export of monitored resources"""
    import csv
    from io import StringIO
    
    resources = Configuration.query.all()
    
    output = StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'ID', 'Resource Name', 'Resource Type', 'Source', 
        'Resource ID', 'Last Updated'
    ])
    
    for resource in resources:
        writer.writerow([
            resource.id,
            resource.resource_name,
            resource.resource_type,
            resource.source,
            resource.resource_id,
            resource.last_updated.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    output.seek(0)
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment;filename=resources_export_{timestamp}.csv'
        }
    )

def export_resources_json():
    """Generate JSON export of monitored resources"""
    import json
    
    resources_data = []
    resources = Configuration.query.all()
    
    for resource in resources:
        resources_data.append({
            'id': resource.id,
            'resource_name': resource.resource_name,
            'resource_type': resource.resource_type,
            'source': resource.source,
            'resource_id': resource.resource_id,
            'last_updated': resource.last_updated.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return Response(
        json.dumps(resources_data, indent=2),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment;filename=resources_export_{timestamp}.json'
        }
    )

def export_signin_csv(start_date):
    """Generate CSV export of sign-in logs"""
    import csv
    from io import StringIO
    
    logs = SigningLog.query.filter(
        SigningLog.timestamp >= start_date
    ).order_by(SigningLog.timestamp.desc()).all()
    
    output = StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'ID', 'Timestamp', 'Actor', 'Action', 'Resource',
        'Status', 'Client IP'
    ])
    
    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.actor,
            log.action,
            log.resource,
            log.status,
            log.client_ip
        ])
    
    output.seek(0)
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment;filename=signin_export_{timestamp}.csv'
        }
    )

def export_signin_json(start_date):
    """Generate JSON export of sign-in logs"""
    import json
    
    logs = SigningLog.query.filter(
        SigningLog.timestamp >= start_date
    ).order_by(SigningLog.timestamp.desc()).all()
    
    logs_data = []
    for log in logs:
        logs_data.append({
            'id': log.id,
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'actor': log.actor,
            'action': log.action,
            'resource': log.resource,
            'status': log.status,
            'client_ip': log.client_ip
        })
    
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return Response(
        json.dumps(logs_data, indent=2),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment;filename=signin_export_{timestamp}.json'
        }
    )
