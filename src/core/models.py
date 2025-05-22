"""
Database models for the Azure Drift Detector application.

This module defines the SQLAlchemy models that represent the core data structures
of the application, including users, tenants, configurations, and monitoring data.
"""

from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from src.core.app import db
import logging

logger = logging.getLogger(__name__)

class Tenant(db.Model):
    """
    Represents a tenant in the multi-tenant system.
    
    Each tenant represents a separate organization or customer with their own
    Azure resources and configurations to monitor.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    azure_tenant_id = db.Column(db.String(255))  # Azure AD tenant ID
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    users = db.relationship('User', backref='tenant', lazy='dynamic')
    configurations = db.relationship('Configuration', backref='tenant', lazy='dynamic')
    settings = db.relationship('Settings', backref='tenant', lazy='dynamic')
    
    def __repr__(self):
        return f'<Tenant {self.name}>'

# Association table for many-to-many relationship between users and roles
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    """
    Represents a user in the system.
    
    Users can belong to a tenant and have specific roles that determine their
    permissions within the application. Supports Microsoft authentication.
    """
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    microsoft_id = db.Column(db.String(128), unique=True, nullable=True)  # Microsoft Graph API ID
    access_token = db.Column(db.Text, nullable=True)  # OAuth access token
    refresh_token = db.Column(db.Text, nullable=True)  # OAuth refresh token
    token_expiry = db.Column(db.DateTime, nullable=True)  # Token expiration time
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    
    # Many-to-many relationship with roles
    roles = db.relationship('Role', secondary=user_roles,
                            backref=db.backref('users', lazy='dynamic'))
    
    def set_password(self, password):
        """Securely hash and set the user's password."""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Verify the provided password against the stored hash."""
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role_name):
        """Check if the user has a specific role."""
        return any(role.name == role_name for role in self.roles)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Role(db.Model):
    """
    Represents a role in the system.
    
    Roles define the permissions and access levels that users can have
    within the application.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(256))
    
    def __repr__(self):
        return f'<Role {self.name}>'

class UserRole(db.Model):
    """
    Represents the assignment of a role to a user.
    
    Tracks when and by whom a role was assigned to a user.
    """
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), primary_key=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class Configuration(db.Model):
    """
    Represents the current configuration state of an Azure resource.
    
    Stores the configuration data for various Azure resources being monitored
    for drift detection.
    """
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    source = db.Column(db.String(64), nullable=False)  # Source of the configuration (e.g., 'azure')
    resource_type = db.Column(db.String(64), nullable=False)  # Type of Azure resource
    resource_id = db.Column(db.String(256), nullable=False)  # Azure resource ID
    resource_name = db.Column(db.String(256))
    config_data = db.Column(db.JSON, nullable=False)  # Current configuration state
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.UniqueConstraint('tenant_id', 'source', 'resource_type', 'resource_id'),
    )
    
    def __repr__(self):
        return f'<Configuration {self.source}:{self.resource_type}:{self.resource_name}>'

class ConfigurationHistory(db.Model):
    """
    Tracks changes in resource configurations over time.
    
    Records the history of configuration changes, including the previous and new
    states, and the detected changes between them.
    """
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    configuration_id = db.Column(db.Integer, db.ForeignKey('configuration.id'), nullable=False)
    previous_config = db.Column(db.JSON, nullable=False)  # Previous configuration state
    new_config = db.Column(db.JSON, nullable=False)  # New configuration state
    changes = db.Column(db.JSON, nullable=False)  # Detected changes
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(16))  # Severity level of the change
    configuration = db.relationship('Configuration', backref='history')
    
    def __repr__(self):
        return f'<ConfigurationHistory {self.configuration_id} at {self.changed_at}>'

class SigningLog(db.Model):
    """
    Represents Azure sign-in activity logs.
    
    Stores information about sign-in events from Azure AD, including the actor,
    action, resource, and status of each sign-in attempt.
    """
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    log_id = db.Column(db.String(128), unique=True, nullable=False)  # Azure log ID
    timestamp = db.Column(db.DateTime, nullable=False)  # Time of the sign-in event
    actor = db.Column(db.String(128))  # User or service principal
    action = db.Column(db.String(128))  # Type of sign-in action
    resource = db.Column(db.String(256))  # Resource being accessed
    status = db.Column(db.String(64))  # Success/failure status
    client_ip = db.Column(db.String(64))  # IP address of the client
    log_data = db.Column(db.JSON)  # Complete log data
    ingested_at = db.Column(db.DateTime, default=datetime.utcnow)  # When the log was imported
    
    def __repr__(self):
        return f'<SigningLog {self.log_id}>'

class Settings(db.Model):
    """
    Stores tenant-specific application settings.
    
    Manages configuration settings for each tenant, such as drift detection
    thresholds, notification preferences, and monitoring configurations.
    """
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    key = db.Column(db.String(64), nullable=False)  # Setting key
    value = db.Column(db.JSON, nullable=False)  # Setting value
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    __table_args__ = (
        db.UniqueConstraint('tenant_id', 'key'),
    )

    @classmethod
    def get_settings(cls, tenant_id):
        """
        Retrieve all settings for a tenant.
        
        Args:
            tenant_id: The ID of the tenant
            
        Returns:
            dict: Dictionary of setting key-value pairs
        """
        try:
            settings = {}
            for setting in cls.query.filter_by(tenant_id=tenant_id).all():
                settings[setting.key] = setting.value
            return settings
        except Exception as e:
            logger.exception(f"Error retrieving settings for tenant {tenant_id}: {str(e)}")
            return {}

    @classmethod
    def update_settings(cls, tenant_id, new_settings):
        """
        Update multiple settings for a tenant.
        
        Args:
            tenant_id: The ID of the tenant
            new_settings: Dictionary of setting key-value pairs to update
        """
        try:
            for key, value in new_settings.items():
                setting = cls.query.filter_by(tenant_id=tenant_id, key=key).first()
                if setting:
                    setting.value = value
                else:
                    setting = cls(tenant_id=tenant_id, key=key, value=value)
                    db.session.add(setting)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.exception(f"Error updating settings for tenant {tenant_id}: {str(e)}")
            raise

    def __repr__(self):
        return f'<Settings {self.key}>'

class LoginAttempt(db.Model):
    """
    Tracks user login attempts for security monitoring.
    
    Records information about each login attempt, including the username,
    IP address, success status, and timestamp.
    """
    __tablename__ = 'login_attempt'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<LoginAttempt {self.username} at {self.timestamp}>'
