"""
Export functionality for the Azure Drift Detector application.

This module handles the export of various data types (changes, resources, sign-in logs)
in different formats (CSV, JSON).
"""

import csv
import json
from io import StringIO
from datetime import datetime, timedelta
from flask import Response
from src.core.app import db
from src.core.models import Configuration, ConfigurationHistory, SigningLog

def export_changes_csv(start_date, source='', resource_type='', severity=''):
    """Generate CSV export of configuration changes"""
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
    logs = SigningLog.query.filter(
        SigningLog.timestamp >= start_date
    ).order_by(SigningLog.timestamp.desc()).all()
    
    output = StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'ID', 'User ID', 'App ID', 'IP Address', 
        'Location', 'Status', 'Timestamp'
    ])
    
    for log in logs:
        writer.writerow([
            log.id,
            log.user_id,
            log.app_id,
            log.ip_address,
            log.location,
            log.status,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
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
    logs = SigningLog.query.filter(
        SigningLog.timestamp >= start_date
    ).order_by(SigningLog.timestamp.desc()).all()
    
    logs_data = []
    for log in logs:
        logs_data.append({
            'id': log.id,
            'user_id': log.user_id,
            'app_id': log.app_id,
            'ip_address': log.ip_address,
            'location': log.location,
            'status': log.status,
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return Response(
        json.dumps(logs_data, indent=2),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment;filename=signin_export_{timestamp}.json'
        }
    ) 