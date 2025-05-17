import os

# Application configuration
class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SESSION_SECRET', os.urandom(24))
    DEBUG = os.environ.get('DEBUG', 'True').lower() in ['true', '1', 't']
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Azure/Microsoft configuration
    AZURE_CLIENT_ID = os.environ.get('AZURE_CLIENT_ID')
    AZURE_CLIENT_SECRET = os.environ.get('AZURE_CLIENT_SECRET')
    AZURE_TENANT_ID = os.environ.get('AZURE_TENANT_ID', 'common')
    
    # Polling interval in minutes
    POLLING_INTERVAL = int(os.environ.get('POLLING_INTERVAL', '30'))
    
    # Security configuration
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ['true', '1', 't']
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Application settings
    APP_NAME = "Azure Drift Detector"
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
