

import pytest
import json
from datetime import datetime, timedelta
from flask import url_for

from app import app, db
from models import Configuration, ConfigurationHistory, SigningLog


def test_dashboard_stats_unauthorized(client):
    """Test dashboard stats API endpoint requires authentication."""
    response = client.get('/api/dashboard/stats')
    assert response.status_code == 401


def test_dashboard_stats(client, regular_user_credentials):
    """Test dashboard stats API returns correct statistics."""
    # Login first
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/api/dashboard/stats')
    assert response.status_code == 200
    
    # Check response structure
    data = json.loads(response.data)
    assert 'counts' in data
    assert 'changes_distribution' in data
    assert 'recent_changes' in data
    
    # Verify the structure of counts data
    assert 'total_resources' in data['counts']
    assert 'critical_changes' in data['counts']
    assert 'recent_changes' in data['counts']
    assert 'signin_events' in data['counts']


def test_change_details_api(client, regular_user_credentials, app):
    """Test change details API endpoint."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    with app.app_context():
        config = Configuration()
        config.source = 'azure'
        config.resource_type = 'VM'
        config.resource_id = '/subscriptions/123/resourceGroups/test/providers/Microsoft.Compute/virtualMachines/test-vm'
        config.resource_name = 'test-vm'
        config.config_data = {'name': 'test-vm', 'size': 'Standard_D2s_v3', 'location': 'eastus'}
        db.session.add(config)
        db.session.commit()
        
        history = ConfigurationHistory()
        history.configuration_id = config.id
        history.previous_config = {'name': 'test-vm', 'size': 'Standard_D2s_v3', 'location': 'eastus'}
        history.new_config = {'name': 'test-vm', 'size': 'Standard_D4s_v3', 'location': 'eastus'}
        history.changes = {'values_changed': {"root['size']": {'new_value': 'Standard_D4s_v3', 'old_value': 'Standard_D2s_v3'}}}
        history.severity = 'medium'
        db.session.add(history)
        db.session.commit()
        
        change_id = history.id
    
    response = client.get(f'/api/changes/{change_id}')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'id' in data
    assert 'resource_name' in data
    assert 'resource_type' in data
    assert 'source' in data
    assert 'changes' in data
    assert 'severity' in data
    assert 'changed_at' in data
    
    assert data['severity'] == 'medium'
    assert data['resource_name'] == 'test-vm'
    assert data['resource_type'] == 'VM'
    assert data['source'] == 'azure'


def test_reports_api(client, regular_user_credentials):
    """Test reports API endpoint."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    response = client.get('/api/reports?page=1&limit=10')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'reports' in data
    assert 'total' in data
    assert 'page' in data
    assert 'pages' in data
    
    # Verify pagination parameters
    assert data['page'] == 1
    assert isinstance(data['total'], int)
    assert isinstance(data['reports'], list)


def test_resource_types_api(client, regular_user_credentials, app):
    """Test resource types API endpoint."""
    client.post('/login', data={
        'email': regular_user_credentials['email'],
        'password': regular_user_credentials['password']
    })
    
    with app.app_context():
        config1 = Configuration()
        config1.source = 'azure'
        config1.resource_type = 'VM'
        config1.resource_id = '/subscriptions/123/resourceGroups/test/providers/Microsoft.Compute/virtualMachines/vm1'
        config1.resource_name = 'vm1'
        config1.config_data = {'name': 'vm1'}
        
        config2 = Configuration()
        config2.source = 'azure'
        config2.resource_type = 'Storage'
        config2.resource_id = '/subscriptions/123/resourceGroups/test/providers/Microsoft.Storage/storageAccounts/storage1'
        config2.resource_name = 'storage1'
        config2.config_data = {'name': 'storage1'}
        
        db.session.add(config1)
        db.session.add(config2)
        db.session.commit()
    
    response = client.get('/api/resource-types')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert isinstance(data, list)
    
    assert 'VM' in data
    assert 'Storage' in data


def test_api_requires_authentication(client):
    """Test all API endpoints require authentication."""
    api_endpoints = [
        '/api/dashboard/stats',
        '/api/reports',
        '/api/resource-types',
        '/api/users',
        '/api/settings',
    ]
    
    for endpoint in api_endpoints:
        response = client.get(endpoint)
        assert response.status_code in [401, 403, 404]


def test_admin_api_endpoints(client, admin_user_credentials):
    """Test admin-only API endpoints."""
    client.post('/login', data={
        'email': admin_user_credentials['email'],
        'password': admin_user_credentials['password']
    })
    
    response = client.get('/api/users')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert isinstance(data, list)
    
    assert len(data) > 0
    assert 'id' in data[0]
    assert 'username' in data[0]
    assert 'email' in data[0]
    assert 'roles' in data[0]