
import os
import pytest
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

from app import app as flask_app, db
from models import User, Role


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    flask_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost.localdomain',
    })

    with flask_app.app_context():
        db.create_all()
        
        admin_role = Role(name='admin', description='Administrator role with full access')
        operator_role = Role(name='operator', description='Operator role with monitoring access')
        user_role = Role(name='user', description='Regular user with read-only access')
        
        db.session.add_all([admin_role, operator_role, user_role])
        db.session.commit()
        
        admin_user = User(
            username='admin_user',
            email='admin@example.com',
            password_hash=generate_password_hash('adminpass'),
            first_name='Admin',
            last_name='User',
            active=True,
            last_login=datetime.utcnow()
        )
        admin_user.roles.append(admin_role)
        
        operator_user = User(
            username='operator_user',
            email='operator@example.com',
            password_hash=generate_password_hash('operatorpass'),
            first_name='Operator',
            last_name='User',
            active=True,
            last_login=datetime.utcnow()
        )
        operator_user.roles.append(operator_role)
        
        regular_user = User(
            username='regular_user',
            email='user@example.com',
            password_hash=generate_password_hash('userpass'),
            first_name='Regular',
            last_name='User',
            active=True,
            last_login=datetime.utcnow()
        )
        regular_user.roles.append(user_role)
        
        db.session.add_all([admin_user, operator_user, regular_user])
        db.session.commit()
        
        yield flask_app
        
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test CLI runner for the app."""
    return app.test_cli_runner()


@pytest.fixture
def admin_user_credentials():
    """Admin user credentials for testing."""
    return {
        'email': 'admin@example.com',
        'password': 'adminpass',
        'user_id': 1
    }


@pytest.fixture
def regular_user_credentials():
    """Regular user credentials for testing."""
    return {
        'email': 'user@example.com',
        'password': 'userpass',
        'user_id': 3
    }


@pytest.fixture
def operator_user_credentials():
    """Operator user credentials for testing."""
    return {
        'email': 'operator@example.com',
        'password': 'operatorpass',
        'user_id': 2
    }