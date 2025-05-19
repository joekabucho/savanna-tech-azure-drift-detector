"""
Routes package for the Azure Drift Detector application.

This package contains all the route modules for the application.
"""

from src.api.routes.dashboard import dashboard, get_dashboard_stats
from src.api.routes.reports import reports, export_report
from src.api.routes.settings import settings
from src.api.routes.users import users

__all__ = [
    'dashboard',
    'get_dashboard_stats',
    'reports',
    'export_report',
    'settings',
    'users'
] 