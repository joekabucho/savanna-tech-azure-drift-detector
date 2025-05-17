import json
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import flash, redirect, url_for, request
from flask_login import current_user

logger = logging.getLogger(__name__)

def format_datetime(dt):
    """Format datetime for display"""
    if not dt:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def format_timeago(dt):
    """Format datetime as relative time ago"""
    if not dt:
        return "N/A"
    
    now = datetime.utcnow()
    diff = now - dt
    
    if diff.days > 30:
        return f"{diff.days // 30} months ago"
    elif diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds >= 3600:
        return f"{diff.seconds // 3600} hours ago"
    elif diff.seconds >= 60:
        return f"{diff.seconds // 60} minutes ago"
    else:
        return "just now"

def format_change_type(change_type):
    """Convert DeepDiff change type to human-readable format"""
    change_map = {
        'values_changed': 'Value changed',
        'type_changes': 'Type changed',
        'dictionary_item_added': 'Item added',
        'dictionary_item_removed': 'Item removed',
        'iterable_item_added': 'Array item added',
        'iterable_item_removed': 'Array item removed'
    }
    return change_map.get(change_type, change_type)

def format_severity(severity):
    """Format severity level with appropriate styling"""
    severity_map = {
        'low': '<span class="badge bg-info">Low</span>',
        'medium': '<span class="badge bg-warning">Medium</span>',
        'high': '<span class="badge bg-danger">High</span>',
        'critical': '<span class="badge bg-danger fw-bold">Critical</span>'
    }
    return severity_map.get(severity, '<span class="badge bg-secondary">Unknown</span>')

def format_json_path(path):
    """Convert DeepDiff path format to readable format"""
    if path.startswith('root'):
        clean_path = path[5:]
        clean_path = clean_path.replace("']['", ".")
        clean_path = clean_path.replace("['", ".")
        clean_path = clean_path.replace("']", "")
        return clean_path
    return path

def safe_json_serialize(obj):
    """Safely serialize object to JSON, handling datetime objects"""
    def default_handler(o):
        if isinstance(o, datetime):
            return o.isoformat()
        raise TypeError(f"Object of type {type(o)} is not JSON serializable")
    
    return json.dumps(obj, default=default_handler)

def truncate_string(string, length=50):
    """Truncate a string to specified length and add ellipsis if needed"""
    if not string:
        return ""
    if len(string) <= length:
        return string
    return string[:length] + "..."

def parse_json_changes(changes_json):
    """Parse JSON changes from DeepDiff format to a more readable format"""
    if not changes_json:
        return []
    
    # Ensure we have a dictionary
    if isinstance(changes_json, str):
        changes_json = json.loads(changes_json)
    
    result = []
    
    for change_type, changes in changes_json.items():
        for path, details in changes.items():
            friendly_path = format_json_path(path)
            
            if change_type == 'values_changed' or change_type == 'type_changes':
                old_value = details.get('old_value', 'N/A')
                new_value = details.get('new_value', 'N/A')
                
                if isinstance(old_value, str) and len(old_value) > 100:
                    old_value = truncate_string(old_value, 100)
                if isinstance(new_value, str) and len(new_value) > 100:
                    new_value = truncate_string(new_value, 100)
                
                result.append({
                    'type': format_change_type(change_type),
                    'path': friendly_path,
                    'old_value': old_value,
                    'new_value': new_value
                })
            else:
                value = details.get('value', 'N/A')
                
                if isinstance(value, str) and len(value) > 100:
                    value = truncate_string(value, 100)
                
                result.append({
                    'type': format_change_type(change_type),
                    'path': friendly_path,
                    'value': value
                })
    
    return result

def admin_required(f):
    """Decorator for views that require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.has_role('admin'):
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def operator_required(f):
    """Decorator for views that require operator role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        
        if not (current_user.has_role('admin') or current_user.has_role('operator')):
            flash('You need operator privileges to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function
