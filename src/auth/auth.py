"""
Authentication module for the Azure Drift Detector application.

This module handles user authentication, including:
- Local username/password authentication
- Microsoft OAuth integration
- Role-based access control
- Login attempt tracking and rate limiting
- Session management
"""

from dotenv import load_dotenv
import os
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
from flask import redirect, url_for, request, session, flash, render_template
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import pathlib

from src.core.app import app, db
from src.core.models import User, Role, UserRole, Tenant, LoginAttempt

# Configure logging
logger = logging.getLogger(__name__)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter to prevent brute force attacks
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Global rate limits
)

# Initialize OAuth for Microsoft authentication
oauth = OAuth(app)

# Load environment variables
project_root = pathlib.Path(__file__).parent.parent.parent.resolve()
dotenv_path = project_root / ".env"
print(f"[DEBUG] Looking for .env file at: {dotenv_path}")
print(f"[DEBUG] .env file exists: {dotenv_path.exists()}")

# Load environment variables
load_dotenv(dotenv_path=dotenv_path)

# Debug: Print loaded Azure OIDC config values
print("[DEBUG] Environment variables loaded:")
print(f"[DEBUG] AZURE_TENANT_ID: {os.environ.get('AZURE_TENANT_ID')}")
print(f"[DEBUG] AZURE_CLIENT_ID: {os.environ.get('AZURE_CLIENT_ID')}")
print(f"[DEBUG] AZURE_CLIENT_SECRET: {'*' * 8 if os.environ.get('AZURE_CLIENT_SECRET') else None}")
print(f"[DEBUG] AZURE_SUBSCRIPTION_ID: {os.environ.get('AZURE_SUBSCRIPTION_ID')}")

# Microsoft OAuth configuration
azure_client_id = "cc3c5562-ad5d-4b7f-aa97-04be2f286894"
azure_client_secret = "~Hc8Q~-Tnvzqk4QNbH-guHofTd7R1ulF452DgcaW"
azure_tenant_id = "2b3c29de-9f5a-4ec0-b8a7-6ca431fe6976"


# azure_client_id = os.environ.get("AZURE_CLIENT_ID")
# azure_client_secret = os.environ.get("AZURE_CLIENT_SECRET")
# azure_tenant_id = os.environ.get("AZURE_TENANT_ID")

# Define microsoft variable with a default value
microsoft = None

# Register Microsoft OAuth provider if credentials are available
if azure_client_id and azure_client_secret and azure_tenant_id:
    print(f"[DEBUG] Registering Microsoft OAuth with tenant ID: {azure_tenant_id}")
    microsoft = oauth.register(
        name='microsoft',
        client_id=azure_client_id,
        client_secret=azure_client_secret,
        server_metadata_url=f'https://login.microsoftonline.com/{azure_tenant_id}/v2.0/.well-known/openid-configuration',
        authorize_url=f'https://login.microsoftonline.com/{azure_tenant_id}/oauth2/v2.0/authorize',
        token_url=f'https://login.microsoftonline.com/{azure_tenant_id}/oauth2/v2.0/token',
        client_kwargs={
            'scope': 'openid email profile offline_access https://graph.microsoft.com/.default',
            'redirect_uri': 'http://localhost:5000/authorize/microsoft',
            'prompt': 'select_account',
        },
    )
else:
    logger.warning("Microsoft OAuth not configured: missing required credentials")
    if not azure_client_id:
        logger.warning("Missing AZURE_CLIENT_ID")
    if not azure_client_secret:
        logger.warning("Missing AZURE_CLIENT_SECRET")
    if not azure_tenant_id:
        logger.warning("Missing AZURE_TENANT_ID")

def role_required(role_name):
    """
    Decorator for role-based access control.
    
    Args:
        role_name (str): The name of the role required to access the decorated function
        
    Returns:
        function: Decorated function that checks for the required role
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            if not current_user.has_role(role_name):
                flash(f'You need {role_name} privileges to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_login_attempts(username):
    """
    Check if a user has exceeded the maximum number of login attempts.
    
    Args:
        username (str): The username to check
        
    Returns:
        bool: True if user can attempt login, False if blocked
    """
    recent_attempts = LoginAttempt.query.filter(
        LoginAttempt.username == username,
        LoginAttempt.timestamp > datetime.utcnow() - timedelta(minutes=15)
    ).count()
    
    if recent_attempts >= 5:
        return False
    return True

def record_login_attempt(username, success):
    """
    Record a login attempt in the database.
    
    Args:
        username (str): The username that attempted to log in
        success (bool): Whether the login attempt was successful
    """
    attempt = LoginAttempt(
        username=username,
        ip_address=request.remote_addr,
        success=success,
        timestamp=datetime.utcnow()
    )
    db.session.add(attempt)
    db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    """
    Handle user login.
    
    Supports both local username/password authentication and Microsoft OAuth.
    Implements rate limiting and login attempt tracking.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error = "Username and password are required"
        else:
            if not check_login_attempts(username):
                error = "Too many failed attempts. Please try again in 15 minutes."
            else:
                user = User.query.filter_by(username=username).first()
                
                if user is None or not user.check_password(password):
                    record_login_attempt(username, False)
                    error = "Invalid username or password"
                elif not user.active:
                    error = "Your account has been deactivated"
                else:
                    record_login_attempt(username, True)
                    login_user(user)
                    user.last_login = datetime.utcnow()
                    db.session.commit()
                    
                    next_page = request.args.get('next')
                    if not next_page or not next_page.startswith('/'):
                        next_page = url_for('dashboard')
                        
                    flash('Login successful!', 'success')
                    return redirect(next_page)
    
    # Check if Microsoft OAuth is configured
    ms_auth_enabled = bool(azure_client_id and azure_client_secret)
    
    return render_template('login.html', error=error, ms_auth_enabled=ms_auth_enabled)

@app.route('/login/microsoft')
@csrf.exempt  # Exempt CSRF for OAuth redirect
def login_microsoft():
    """
    Initiate Microsoft OAuth login flow.
    
    Redirects user to Microsoft's login page if OAuth is properly configured.
    """
    if not azure_client_id or not azure_client_secret:
        flash('Microsoft authentication is not configured', 'danger')
        return redirect(url_for('login'))
    
    redirect_uri = 'http://localhost:5000/authorize/microsoft'
    logger.info(f"Using redirect URI: {redirect_uri}")
    if microsoft is None:
        flash('Microsoft authentication is not configured properly', 'danger')
        return redirect(url_for('login'))
    return microsoft.authorize_redirect(redirect_uri)

@app.route('/authorize/microsoft')
@csrf.exempt  # Exempt CSRF for OAuth callback
def authorize_microsoft():
    """
    Handle Microsoft OAuth callback.
    
    Processes the OAuth response, creates or updates user account,
    and manages authentication tokens.
    """
    try:
        if microsoft is None:
            flash('Microsoft authentication is not configured properly', 'danger')
            return redirect(url_for('login'))
        
        logger.info(f"Received callback at: {request.url}")
        token = microsoft.authorize_access_token()
        resp = microsoft.get('https://graph.microsoft.com/v1.0/me')
        profile = resp.json()
        
        # Get Microsoft ID
        microsoft_id = profile.get('id')
        
        # Find or create user
        user = User.query.filter_by(microsoft_id=microsoft_id).first()
        if not user:
            # Check if email already exists
            email = profile.get('mail') or profile.get('userPrincipalName')
            existing_user = User.query.filter_by(email=email).first()
            
            if existing_user:
                # Link Microsoft account to existing user
                existing_user.microsoft_id = microsoft_id
                existing_user.access_token = token.get('access_token')
                existing_user.refresh_token = token.get('refresh_token')
                existing_user.token_expiry = datetime.utcnow() + timedelta(seconds=token.get('expires_in', 3600))
                user = existing_user
            else:
                # Create new user
                user = User()
                user.username = email.split('@')[0] if email else f"ms_user_{microsoft_id[:8]}"
                user.email = email
                user.first_name = profile.get('givenName', '')
                user.last_name = profile.get('surname', '')
                user.microsoft_id = microsoft_id
                user.access_token = token.get('access_token')
                user.refresh_token = token.get('refresh_token')
                user.token_expiry = datetime.utcnow() + timedelta(seconds=token.get('expires_in', 3600))
                user.password_hash = generate_password_hash(os.urandom(24).hex())  # Random password for MS auth users
                
                # Add default role (viewer)
                viewer_role = Role.query.filter_by(name='viewer').first()
                if not viewer_role:
                    viewer_role = Role()
                    viewer_role.name = 'viewer'
                    viewer_role.description = 'Basic access to view resources'
                    db.session.add(viewer_role)
                
                user.roles.append(viewer_role)
                db.session.add(user)
                
        else:
            # Update tokens
            user.access_token = token.get('access_token')
            user.refresh_token = token.get('refresh_token')
            user.token_expiry = datetime.utcnow() + timedelta(seconds=token.get('expires_in', 3600))
        
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        login_user(user)
        flash('Login successful via Microsoft!', 'success')
        return redirect(url_for('dashboard'))
        
    except OAuthError as e:
        logger.error(f"OAuth error: {str(e)}")
        flash(f'Authentication error: {str(e)}', 'danger')
        return redirect(url_for('login'))
    except Exception as e:
        logger.exception("Error during Microsoft authentication")
        flash('An unexpected error occurred during authentication', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    """
    Handle user logout.
    
    Clears the user's session and redirects to the login page.
    """
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    """
    Display user profile page.
    
    Shows user information and settings.
    """
    return render_template('profile.html')

def create_default_roles():
    """
    Initialize default roles in the database.
    
    Creates the basic role structure if it doesn't exist:
    - viewer: Basic access to view resources
    - editor: Can modify configurations
    - admin: Full administrative access
    """
    with app.app_context():
        # Ensure a default tenant exists
        default_tenant = Tenant.query.filter_by(name='Default Tenant').first()
        if not default_tenant:
            default_tenant = Tenant(name='Default Tenant', azure_tenant_id=os.environ.get('AZURE_TENANT_ID'))
            db.session.add(default_tenant)
            db.session.commit()

        default_tenant_id = default_tenant.id

        default_roles = [
            {'name': 'admin', 'description': 'Full system access'},
            {'name': 'operator', 'description': 'Can manage configurations and view reports'},
            {'name': 'viewer', 'description': 'Can view dashboard and reports only'}
        ]
        
        # Create roles if they don't exist
        for role_data in default_roles:
            role = Role.query.filter_by(name=role_data['name']).first()
            if not role:
                role = Role(**role_data)
                db.session.add(role)
        
        # Commit to ensure roles are created before assigning to users
        db.session.commit()
        
        # Get role objects for assignment
        admin_role = Role.query.filter_by(name='admin').first()
        operator_role = Role.query.filter_by(name='operator').first()
        viewer_role = Role.query.filter_by(name='viewer').first()
        
        # Create test users if they don't exist
        test_users = [
            {
                'username': 'admin',
                'email': 'admin@example.com',
                'password': 'adminpass',
                'first_name': 'Admin',
                'last_name': 'User',
                'roles': [admin_role]
            },
            {
                'username': 'user',
                'email': 'user@example.com',
                'password': 'userpass',
                'first_name': 'Regular',
                'last_name': 'User',
                'roles': [viewer_role]
            },
            {
                'username': 'operator',
                'email': 'operator@example.com',
                'password': 'operatorpass',
                'first_name': 'Operator',
                'last_name': 'User',
                'roles': [operator_role]
            }
        ]
        
        # First, delete any existing test users to ensure clean slate
        for user_data in test_users:
            existing_user = User.query.filter_by(email=user_data['email']).first()
            if existing_user:
                logger.info(f"Removing existing user: {existing_user.username}")
                db.session.delete(existing_user)
        
        db.session.commit()
        
        # Now create all test users
        for user_data in test_users:
            # Create new user
            user = User()
            user.username = user_data['username']
            user.email = user_data['email']
            user.first_name = user_data['first_name']
            user.last_name = user_data['last_name']
            user.active = True
            user.set_password(user_data['password'])
            user.tenant_id = default_tenant_id  # Assign tenant_id
            
            # Assign roles
            for role in user_data['roles']:
                user.roles.append(role)
            
            db.session.add(user)
            logger.info(f"Created test user: {user.username}")
        
        # Commit all changes
        db.session.commit()
 