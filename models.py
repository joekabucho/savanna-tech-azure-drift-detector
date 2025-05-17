from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    microsoft_id = db.Column(db.String(128), unique=True, nullable=True)
    access_token = db.Column(db.Text, nullable=True)
    refresh_token = db.Column(db.Text, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    
    roles = db.relationship('Role', secondary=user_roles,
                            backref=db.backref('users', lazy='dynamic'))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(256))
    
    def __repr__(self):
        return f'<Role {self.name}>'

class UserRole(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), primary_key=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class Configuration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(64), nullable=False)
    resource_type = db.Column(db.String(64), nullable=False)
    resource_id = db.Column(db.String(256), nullable=False)
    resource_name = db.Column(db.String(256))
    config_data = db.Column(db.JSON, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('source', 'resource_type', 'resource_id'),)
    
    def __repr__(self):
        return f'<Configuration {self.source}:{self.resource_type}:{self.resource_name}>'

class ConfigurationHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    configuration_id = db.Column(db.Integer, db.ForeignKey('configuration.id'), nullable=False)
    previous_config = db.Column(db.JSON, nullable=False)
    new_config = db.Column(db.JSON, nullable=False)
    changes = db.Column(db.JSON, nullable=False)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(16))
    configuration = db.relationship('Configuration', backref='history')
    
    def __repr__(self):
        return f'<ConfigurationHistory {self.configuration_id} at {self.changed_at}>'

class SigningLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.String(128), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    actor = db.Column(db.String(128))
    action = db.Column(db.String(128))
    resource = db.Column(db.String(256))
    status = db.Column(db.String(64))
    client_ip = db.Column(db.String(64))
    log_data = db.Column(db.JSON)
    ingested_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<SigningLog {self.log_id}>'

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.JSON, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    def get_settings(cls):
        settings = {}
        for setting in cls.query.all():
            settings[setting.key] = setting.value
        return settings

    @classmethod
    def update_settings(cls, new_settings):
        for key, value in new_settings.items():
            setting = cls.query.filter_by(key=key).first()
            if setting:
                setting.value = value
            else:
                setting = cls(key=key, value=value)
                db.session.add(setting)
        db.session.commit()

    def __repr__(self):
        return f'<Settings {self.key}>'
