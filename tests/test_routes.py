"""
Tests for web routes in the Azure Drift Detector application.
"""

import pytest
from flask import url_for


def test_index_route_redirect(client):
    """Test index route redirects to login or dashboard."""
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 302  # Redirect
    
    # Should redirect to login if not authenticated
    assert '/login' in response.headers['Location'] or '/dashboard' in response.headers['Location']


def test_dashboard_route_authenticated(client, regular_user_credentials):
    """Test dashboard route for authenticated users."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b'Dashboard' in response.data
    
    assert b'Resource Configurations' in response.data
    assert b'Critical Changes' in response.data
    assert b'Recent Changes' in response.data


def test_dashboard_route_unauthenticated(client):
    """Test dashboard route for unauthenticated users."""
    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data


def test_reports_route_authenticated(client, regular_user_credentials):
    """Test reports route for authenticated users."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/reports')
    assert response.status_code == 200
    assert b'Reports' in response.data
    
    assert b'Filter' in response.data
    assert b'Export' in response.data


def test_reports_route_unauthenticated(client):
    """Test reports route for unauthenticated users."""
    response = client.get('/reports', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data


def test_settings_route_authenticated(client, regular_user_credentials):
    """Test settings route for authenticated users."""
    # Login first
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/settings')
    assert response.status_code == 200
    assert b'Settings' in response.data
    
    assert b'Azure Configuration' in response.data
    assert b'Polling Interval' in response.data


def test_settings_route_unauthenticated(client):
    """Test settings route for unauthenticated users."""
    response = client.get('/settings', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data


def test_users_route_admin(client, admin_user_credentials):
    """Test users route for admin users."""
    client.post('/login', data={
        'email': admin_user_credentials['email'],
        'password': admin_user_credentials['password']
    })
    
    response = client.get('/users')
    assert response.status_code == 200
    assert b'User Management' in response.data
    
    assert b'Add User' in response.data
    assert b'Role' in response.data


def test_users_route_non_admin(client, regular_user_credentials):
    """Test users route for non-admin users."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/users', follow_redirects=True)
    assert response.status_code == 200
    assert b'You do not have permission to access this page' in response.data


def test_export_route(client, regular_user_credentials):
    """Test export functionality."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/export/changes?format=csv&days=7')
    assert response.status_code in [200, 302]  
    
    if response.status_code == 200:
        assert 'text/csv' in response.content_type