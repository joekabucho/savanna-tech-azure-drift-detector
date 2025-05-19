"""
Routes module for the Azure Drift Detector application.

This module serves as the main entry point for all routes.
It imports and exposes routes from the routes package.
"""

from src.api.routes import (
    dashboard,
    get_dashboard_stats,
    reports,
    export_report,
    settings,
    users
)

# Re-export all routes
__all__ = [
    'dashboard',
    'get_dashboard_stats',
    'reports',
    'export_report',
    'settings',
    'users'
]
