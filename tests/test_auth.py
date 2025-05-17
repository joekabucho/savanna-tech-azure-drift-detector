"""
Tests for authentication functionality in the Azure Drift Detector application.
"""

import pytest
from flask import session, url_for


def test_login_page(client):
    """Test login page loads correctly."""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data
    assert b'Email address' in response.data
    assert b'Password' in response.data


def test_login_success(client, regular_user_credentials):
    """Test successful login with valid credentials."""
    response = client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Dashboard' in response.data


def test_login_invalid_credentials(client):
    """Test login fails with invalid credentials."""
    response = client.post('/login', data={
        'email': 'nonexistent@example.com',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Login' in response.data
    assert b'Invalid email or password' in response.data


def test_logout(client, regular_user_credentials):
    """Test logout functionality."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data


def test_profile_access_authenticated(client, regular_user_credentials):
    """Test authenticated user can access profile page."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/profile')
    assert response.status_code == 200
    assert b'Profile' in response.data


def test_profile_access_unauthenticated(client):
    """Test unauthenticated user cannot access profile page."""
    response = client.get('/profile', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data
    assert b'Please log in to access this page' in response.data


def test_admin_access_authorized(client, admin_user_credentials):
    """Test admin user can access admin-only pages."""
    client.post('/login', data={
        'email': admin_user_credentials['email'],
        'password': admin_user_credentials['password']
    })
    
    response = client.get('/users')
    assert response.status_code == 200
    assert b'User Management' in response.data


def test_admin_access_unauthorized(client, regular_user_credentials):
    """Test regular user cannot access admin-only pages."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/users', follow_redirects=True)
    assert response.status_code == 200
    assert b'You do not have permission to access this page' in response.data