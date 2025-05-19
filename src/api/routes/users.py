"""
User management routes for the Azure Drift Detector application.

This module handles user management functionality, including:
- User listing and details
- Role management
- User creation and updates
"""

import logging
from flask import render_template, redirect, url_for, flash
from flask_login import login_required

from src.core.app import app
from src.core.utils import admin_required

logger = logging.getLogger(__name__)

@app.route('/users')
@login_required
@admin_required
def users():
    """
    User management page.
    
    Displays a page where administrators can manage users and their roles.
    Requires admin role.
    """
    return render_template('users.html') 