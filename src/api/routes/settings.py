"""
Settings routes for the Azure Drift Detector application.

This module handles application settings and configuration management.
"""

import logging
from flask import render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from src.core.app import app
from src.core.utils import operator_required

logger = logging.getLogger(__name__)

@app.route('/settings')
@login_required
@operator_required
def settings():
    """
    Settings page for application configuration.
    
    Displays a page where operators and admins can configure application settings.
    Requires operator or admin role.
    """
    return render_template('settings.html') 