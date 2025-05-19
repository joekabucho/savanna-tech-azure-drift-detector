"""
Report routes for the Azure Drift Detector application.

This module handles report generation and viewing functionality.
"""

import logging
from datetime import datetime, timedelta
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required

from src.core.app import app
from src.api.routes.export import (
    export_changes_csv, export_changes_json,
    export_resources_csv, export_resources_json,
    export_signin_csv, export_signin_json
)

logger = logging.getLogger(__name__)

@app.route('/reports')
@login_required
def reports():
    """
    Report page for viewing detailed configuration changes.
    
    Displays a page where users can view and export various types of reports.
    """
    return render_template('reports.html')

@app.route('/export/<report_type>')
@login_required
def export_report(report_type):
    """
    Handle report exports in various formats.
    
    Args:
        report_type (str): Type of report to export ('changes', 'resources', or 'signin')
    
    Returns:
        Response: CSV or JSON file download
    """
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