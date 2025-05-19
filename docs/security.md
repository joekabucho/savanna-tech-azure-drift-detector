# Security Implementation Guide

## Authentication & Authorization

### OAuth2/OIDC Integration

The application supports both OAuth2/OIDC and local authentication:

```python
# OAuth2/OIDC Configuration
OAUTH2_CLIENT_ID = os.getenv('OAUTH2_CLIENT_ID')
OAUTH2_CLIENT_SECRET = os.getenv('OAUTH2_CLIENT_SECRET')
OAUTH2_AUTHORIZE_URL = os.getenv('OAUTH2_AUTHORIZE_URL')
OAUTH2_TOKEN_URL = os.getenv('OAUTH2_TOKEN_URL')
OAUTH2_USERINFO_URL = os.getenv('OAUTH2_USERINFO_URL')
```

### Password Security

Passwords are securely hashed using Argon2:

```python
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # Memory usage in KiB
    parallelism=4,      # Number of parallel threads
    hash_len=32,        # Length of the hash in bytes
    salt_len=16         # Length of the salt in bytes
)

# Hashing a password
hashed_password = ph.hash(password)

# Verifying a password
try:
    ph.verify(hashed_password, password)
except Exception:
    # Invalid password
    pass
```

### Session Security

```python
# Session Configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_COOKIE_NAME='_azure_drift_session'
)
```

### CSRF Protection

CSRF protection is implemented using Flask-WTF:

```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# In forms
<form method="POST">
    {{ csrf_token() }}
    <!-- form fields -->
</form>

# In API requests
headers = {
    'X-CSRF-Token': csrf_token
}
```

### Brute Force Protection

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Rate limit login attempts
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # Login logic
    pass
```

## API Security

### API Authentication

```python
from functools import wraps
from flask import request, abort

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not validate_api_key(api_key):
            abort(401)
        return f(*args, **kwargs)
    return decorated
```

### Request Validation

```python
from marshmallow import Schema, fields, validate

class ResourceSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    type = fields.Str(required=True, validate=validate.OneOf(['vm', 'storage', 'nsg']))
    region = fields.Str(required=True)
```

## Data Security

### Encryption at Rest

```python
from cryptography.fernet import Fernet

# Generate encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Encrypt sensitive data
encrypted_data = cipher_suite.encrypt(sensitive_data.encode())

# Decrypt data
decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
```

### Secure Headers

```python
from flask_talisman import Talisman

Talisman(app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' 'unsafe-eval'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data: https:",
        'connect-src': "'self' https://api.azure.com"
    }
)
```

## Security Monitoring

### Audit Logging

```python
import structlog

logger = structlog.get_logger()

def audit_log(action, user, resource, status):
    logger.info(
        "audit_event",
        action=action,
        user=user,
        resource=resource,
        status=status,
        timestamp=datetime.utcnow().isoformat()
    )
```

### Security Alerts

```python
def security_alert(severity, message, context):
    alert = {
        'severity': severity,
        'message': message,
        'context': context,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    # Send to alerting system
    send_alert(alert)
```

## Security Best Practices

1. **Password Management**
   - Use Argon2 for password hashing
   - Implement password complexity requirements
   - Enforce password rotation policies
   - Store password hashes securely

2. **Session Management**
   - Use secure, HTTP-only cookies
   - Implement session timeouts
   - Rotate session IDs
   - Monitor session activity

3. **API Security**
   - Use API keys for authentication
   - Implement rate limiting
   - Validate all input
   - Use HTTPS for all communications

4. **Data Protection**
   - Encrypt sensitive data at rest
   - Use TLS for data in transit
   - Implement proper access controls
   - Regular security audits

5. **Monitoring and Logging**
   - Log all security events
   - Monitor for suspicious activity
   - Implement alerting for security incidents
   - Regular security reviews

## Security Configuration

Update your `.env` file with these security-related settings:

```bash
# OAuth2/OIDC
OAUTH2_CLIENT_ID=your_client_id
OAUTH2_CLIENT_SECRET=your_client_secret
OAUTH2_AUTHORIZE_URL=https://login.microsoftonline.com/...
OAUTH2_TOKEN_URL=https://login.microsoftonline.com/...
OAUTH2_USERINFO_URL=https://graph.microsoft.com/...

# Security Settings
SESSION_SECRET=your_session_secret
ENCRYPTION_KEY=your_encryption_key
CSRF_SECRET_KEY=your_csrf_secret

# Rate Limiting
RATE_LIMIT_STORAGE_URL=redis://localhost:6379/0
RATE_LIMIT_STRATEGY=fixed-window

# Security Headers
ENABLE_HSTS=true
ENABLE_CSP=true
ENABLE_XSS_PROTECTION=true
```

## Security Checklist

- [ ] OAuth2/OIDC integration configured
- [ ] Password hashing implemented
- [ ] CSRF protection enabled
- [ ] Rate limiting configured
- [ ] Secure headers set
- [ ] Audit logging enabled
- [ ] Security monitoring active
- [ ] Regular security reviews scheduled
- [ ] Incident response plan in place
- [ ] Security documentation updated 