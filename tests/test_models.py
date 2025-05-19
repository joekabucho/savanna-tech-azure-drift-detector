import pytest
from datetime import datetime, timedelta
import json

from src.core.app import db
from src.core.models import User, Role, Configuration, ConfigurationHistory, SigningLog, Tenant


def test_user_model(app):
    """Test User model functionality."""
    with app.app_context():
        # Get default tenant
        tenant = Tenant.query.first()
        assert tenant is not None
        
        user = User()
        user.username = 'testuser'
        user.email = 'test@example.com'
        user.set_password('testpassword')
        user.tenant_id = tenant.id
        
        db.session.add(user)
        db.session.commit()
        
        retrieved_user = User.query.filter_by(username='testuser').first()
        
        assert retrieved_user is not None
        assert retrieved_user.username == 'testuser'
        assert retrieved_user.email == 'test@example.com'
        assert retrieved_user.check_password('testpassword')
        assert not retrieved_user.check_password('wrongpassword')
        assert retrieved_user.tenant_id == tenant.id
        
        assert str(retrieved_user) == f"<User {retrieved_user.username}>"


def test_role_model(app):
    """Test Role model functionality."""
    with app.app_context():
        role = Role()
        role.name = 'test_role'
        role.description = 'Role for testing'
        
        db.session.add(role)
        db.session.commit()
        
        retrieved_role = Role.query.filter_by(name='test_role').first()
        
        assert retrieved_role is not None
        assert retrieved_role.name == 'test_role'
        assert retrieved_role.description == 'Role for testing'
        
        assert str(retrieved_role) == f"<Role {retrieved_role.name}>"


def test_user_role_relationship(app):
    """Test relationship between User and Role models."""
    with app.app_context():
        role = Role()
        role.name = 'test_role2'
        role.description = 'Another role for testing'
        db.session.add(role)
        
        user = User()
        user.username = 'testuser2'
        user.email = 'test2@example.com'
        user.set_password('testpassword')
        
        user.roles.append(role)
        db.session.add(user)
        db.session.commit()
        
        retrieved_user = User.query.filter_by(username='testuser2').first()
        assert retrieved_user is not None
        assert len(retrieved_user.roles) == 1
        assert retrieved_user.roles[0].name == 'test_role2'
        assert retrieved_user.has_role('test_role2')
        assert not retrieved_user.has_role('nonexistent_role')


def test_configuration_model(app):
    """Test Configuration model functionality."""
    with app.app_context():
        # Get default tenant
        tenant = Tenant.query.first()
        assert tenant is not None
        
        config = Configuration()
        config.tenant_id = tenant.id
        config.source = 'azure'
        config.resource_type = 'VM'
        config.resource_id = '/subscriptions/123/resourceGroups/test/providers/Microsoft.Compute/virtualMachines/test-vm'
        config.resource_name = 'test-vm'
        config.config_data = {'name': 'test-vm', 'size': 'Standard_D2s_v3', 'location': 'eastus'}
        
        db.session.add(config)
        db.session.commit()
        
        retrieved_config = Configuration.query.filter_by(resource_id=config.resource_id).first()
        
        assert retrieved_config is not None
        assert retrieved_config.tenant_id == tenant.id
        assert retrieved_config.source == 'azure'
        assert retrieved_config.resource_type == 'VM'
        assert retrieved_config.resource_name == 'test-vm'
        assert retrieved_config.config_data['name'] == 'test-vm'
        assert retrieved_config.config_data['size'] == 'Standard_D2s_v3'
        
        assert str(retrieved_config) == f"<Configuration {retrieved_config.source}/{retrieved_config.resource_type}/{retrieved_config.resource_name}>"


def test_configuration_history_model(app):
    """Test ConfigurationHistory model functionality."""
    with app.app_context():
        # Get default tenant
        tenant = Tenant.query.first()
        assert tenant is not None
        
        config = Configuration()
        config.tenant_id = tenant.id
        config.source = 'azure'
        config.resource_type = 'Storage'
        config.resource_id = '/subscriptions/123/resourceGroups/test/providers/Microsoft.Storage/storageAccounts/teststorage'
        config.resource_name = 'teststorage'
        config.config_data = {'name': 'teststorage', 'sku': 'Standard_LRS', 'location': 'eastus'}
        db.session.add(config)
        db.session.commit()
        
        history = ConfigurationHistory()
        history.tenant_id = tenant.id
        history.configuration_id = config.id
        history.previous_config = {'name': 'teststorage', 'sku': 'Standard_LRS', 'location': 'eastus'}
        history.new_config = {'name': 'teststorage', 'sku': 'Premium_LRS', 'location': 'eastus'}
        history.changes = {'values_changed': {"root['sku']": {'new_value': 'Premium_LRS', 'old_value': 'Standard_LRS'}}}
        history.severity = 'medium'
        
        db.session.add(history)
        db.session.commit()
        
        retrieved_history = ConfigurationHistory.query.filter_by(configuration_id=config.id).first()
        
        assert retrieved_history is not None
        assert retrieved_history.tenant_id == tenant.id
        assert retrieved_history.configuration_id == config.id
        assert retrieved_history.previous_config['sku'] == 'Standard_LRS'
        assert retrieved_history.new_config['sku'] == 'Premium_LRS'
        assert retrieved_history.severity == 'medium'
        assert 'values_changed' in retrieved_history.changes
        
        assert str(retrieved_history) == f"<ConfigurationHistory {retrieved_history.id}>"


def test_signing_log_model(app):
    """Test SigningLog model functionality."""
    with app.app_context():
        # Get default tenant
        tenant = Tenant.query.first()
        assert tenant is not None
        
        # Create a test signing log
        log = SigningLog()
        log.tenant_id = tenant.id
        log.log_id = 'abc123'
        log.timestamp = datetime.utcnow()
        log.actor = 'testuser@example.com'
        log.action = 'SignIn'
        log.resource = 'Microsoft 365'
        log.status = 'Success'
        log.client_ip = '192.168.1.1'
        log.log_data = {'userPrincipalName': 'testuser@example.com', 'appDisplayName': 'Office 365'}
        
        db.session.add(log)
        db.session.commit()
        
        retrieved_log = SigningLog.query.filter_by(log_id='abc123').first()
        
        assert retrieved_log is not None
        assert retrieved_log.tenant_id == tenant.id
        assert retrieved_log.log_id == 'abc123'
        assert retrieved_log.actor == 'testuser@example.com'
        assert retrieved_log.action == 'SignIn'
        assert retrieved_log.resource == 'Microsoft 365'
        assert retrieved_log.status == 'Success'
        assert retrieved_log.client_ip == '192.168.1.1'
        assert retrieved_log.log_data['userPrincipalName'] == 'testuser@example.com'
        
        assert str(retrieved_log) == f"<SigningLog {retrieved_log.log_id}>"