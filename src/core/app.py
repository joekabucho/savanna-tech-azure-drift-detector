"""
Main application module for the Azure Drift Detector.

This module initializes and configures the Flask application with security features,
database connections, and core functionality for detecting configuration drift in Azure resources.
"""

import os
import logging
from datetime import timedelta
from flask import Flask, redirect, url_for, flash, render_template, request
from flask_login import LoginManager, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler
from flask_migrate import Migrate
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
import atexit

# Configure logging with detailed format including timestamp, module name, and log level
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""
    pass

# Initialize SQLAlchemy with custom base class
db = SQLAlchemy(model_class=Base)

# Get the absolute path to the project root directory
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))

# Initialize Flask application with custom template and static folders
app = Flask(__name__, 
           template_folder=os.path.join(project_root, 'templates'),
           static_folder=os.path.join(project_root, 'static'))

# Set secret key first - this is required for CSRF and session management
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# Security configurations for the application
app.config.update(
    # Session security settings
    SESSION_COOKIE_SECURE=True,  # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to cookies
    SESSION_COOKIE_SAMESITE='Lax',  # Protect against CSRF
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),  # Session timeout after 1 hour
    
    # CSRF protection settings
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,  # CSRF token valid for 1 hour
    WTF_CSRF_SECRET_KEY=os.environ.get('CSRF_SECRET_KEY', app.secret_key),
    
    # Remember me cookie security
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax',
    
    # Application security keys
    SECURITY_PASSWORD_SALT=os.environ.get("PASSWORD_SALT", os.urandom(24)),
)

# Initialize security extensions
csrf = CSRFProtect(app)  # Enable CSRF protection
talisman = Talisman(
    app,
    force_https=True,  # Force all connections to use HTTPS
    strict_transport_security=True,  # Enable HSTS
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': [
            "'self'",
            "'unsafe-inline'",
            'cdn.jsdelivr.net',
            'cdnjs.cloudflare.com'
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",
            'cdn.jsdelivr.net',
            'cdnjs.cloudflare.com'
        ],
        'img-src': [
            "'self'",
            'data:',
            'cdn.jsdelivr.net',
            'cdnjs.cloudflare.com'
        ],
        'font-src': [
            "'self'",
            'cdn.jsdelivr.net',
            'cdnjs.cloudflare.com'
        ],
    }
)

# Configure proxy settings for proper handling of forwarded headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Database configuration
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres"):
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    logger.info("Using PostgreSQL database")
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
    logger.info("Using SQLite database")

# Database connection pool settings
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,  # Recycle connections after 5 minutes
    "pool_pre_ping": True,  # Verify connections before use
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database and migrations
db.init_app(app)
migrate = Migrate(app, db)

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = 'Please log in to access this page.'
login_manager.session_protection = 'strong'

# Import required modules
from src.core.models import User, Role, UserRole, Configuration, ConfigurationHistory, SigningLog
import src.auth.auth as auth
from src.api.routes import get_dashboard_stats
from src.drift.azure_poller import poll_azure_configurations

# Initialize background scheduler for Azure configuration polling
scheduler = BackgroundScheduler()
scheduler.add_job(func=poll_azure_configurations, trigger="interval", minutes=30)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

@app.route('/')
def index():
    """
    Root route handler.
    Redirects authenticated users to dashboard, others to login page.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    """
    User loader callback for Flask-Login.
    Retrieves user from database by ID.
    """
    from src.core.models import User
    return User.query.get(int(user_id))

@app.errorhandler(404)
def page_not_found(e):
    """Handler for 404 Not Found errors."""
    return render_template('base.html', error="404 - Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handler for 500 Internal Server errors."""
    return render_template('base.html', error="500 - Internal server error"), 500
