import logging
import json
import os
from datetime import datetime, timedelta

from flask import request, jsonify, Blueprint, abort
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

from app import app, db
from models import (
    User, Role, Configuration, ConfigurationHistory, 
    SigningLog, UserRole, Settings
)
from utils import (
    format_datetime, format_timeago, format_severity, 
    parse_json_changes, admin_required, operator_required
)
from azure_poller import poll_azure_configurations

load_dotenv()
logger = logging.getLogger(__name__)
api_bp = Blueprint('api_blueprint', __name__, url_prefix='/api')

@api_bp.route('/dashboard/stats', methods=['GET'])
@login_required
def dashboard_stats():
    try:
        total_resources = Configuration.query.count()
        
        critical_changes = ConfigurationHistory.query.filter_by(severity='critical').count()
        
        one_day_ago = datetime.utcnow() - timedelta(days=1)
        recent_changes = ConfigurationHistory.query.filter(
            ConfigurationHistory.changed_at >= one_day_ago
        ).count()
        
        signin_events = SigningLog.query.filter(
            SigningLog.timestamp >= one_day_ago
        ).count()
        
        change_distribution = {
            'critical': ConfigurationHistory.query.filter_by(severity='critical').count(),
            'high': ConfigurationHistory.query.filter_by(severity='high').count(),
            'medium': ConfigurationHistory.query.filter_by(severity='medium').count(),
            'low': ConfigurationHistory.query.filter_by(severity='low').count()
        }
        
        timeline_data = {}
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        for i in range(7):
            date = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
            timeline_data[date] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        # Query changes for the last 7 days
        recent_history = ConfigurationHistory.query.filter(
            ConfigurationHistory.changed_at >= seven_days_ago
        ).all()
        
        # Group by date and severity
        for history in recent_history:
            date = history.changed_at.strftime('%Y-%m-%d')
            if date in timeline_data and history.severity:
                timeline_data[date][history.severity] = timeline_data[date].get(history.severity, 0) + 1
        
        # Recent changes list (10 most recent)
        recent_changes_list = []
        recent_history_entries = ConfigurationHistory.query.order_by(
            ConfigurationHistory.changed_at.desc()
        ).limit(10).all()
        
        for history in recent_history_entries:
            config = history.configuration
            
            changes_json = json.loads(history.changes) if history.changes else {}
            change_count = 0
            if changes_json:
                for change_type, changes in changes_json.items():
                    change_count += len(changes)
                change_type = "Multiple Changes" if change_count > 1 else "Configuration Change"
                
                recent_changes_list.append({
                    'id': history.id,
                    'time': format_timeago(history.changed_at),
                    'resource_name': config.resource_name,
                    'resource_type': config.resource_type,
                    'source': config.source,
                    'change_type': change_type,
                    'severity': history.severity,
                    'severity_badge': format_severity(history.severity),
                    'change_count': change_count
                })
        
        return jsonify({
            'total_resources': total_resources,
            'critical_changes': critical_changes,
            'recent_changes': recent_changes,
            'signin_events': signin_events,
            'change_distribution': change_distribution,
            'timeline_data': timeline_data,
            'recent_changes_list': recent_changes_list
        })
        
    except Exception as e:
        logger.exception(f"Error fetching dashboard stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/changes/<int:change_id>', methods=['GET'])
@login_required
def get_change_details(change_id):
    try:
        history = ConfigurationHistory.query.get_or_404(change_id)
        config = history.configuration
        
        # Parse changes for display
        changes_json = json.loads(history.changes) if history.changes else {}
        changes_parsed = parse_json_changes(changes_json)
        
        return jsonify({
            'id': history.id,
            'time': format_datetime(history.changed_at),
            'resource_name': config.resource_name,
            'resource_type': config.resource_type,
            'resource_id': config.resource_id,
            'source': config.source,
            'severity': history.severity,
            'severity_badge': format_severity(history.severity),
            'changes': changes_parsed
        })
        
    except Exception as e:
        logger.exception(f"Error fetching change details: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/reports', methods=['GET'])
@login_required
def get_reports():
    try:
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('pageSize', 10))
        
        source = request.args.get('source', '')
        resource_type = request.args.get('resourceType', '')
        severity = request.args.get('severity', '')
        date_range = int(request.args.get('dateRange', 7))
        start_date = datetime.utcnow() - timedelta(days=date_range)
        
        query = ConfigurationHistory.query.filter(
            ConfigurationHistory.changed_at >= start_date
        ).join(Configuration)
        
        if source:
            query = query.filter(Configuration.source == source)
        
        if resource_type:
            query = query.filter(Configuration.resource_type == resource_type)
        
        if severity:
            query = query.filter(ConfigurationHistory.severity == severity)
        query = query.order_by(ConfigurationHistory.changed_at.desc())
        
        # Get total count for pagination
        total_items = query.count()
        total_pages = (total_items + page_size - 1) // page_size if total_items > 0 else 1
        
        # Paginate results
        paginated_query = query.paginate(page=page, per_page=page_size, error_out=False)
        
        # Prepare data for response
        changes = []
        for history in paginated_query.items:
            config = history.configuration
            
            # Parse changes count
            changes_json = json.loads(history.changes) if history.changes else {}
            change_count = 0
            if changes_json:
                for change_type, changes in changes_json.items():
                    change_count += len(changes)
            
            changes.append({
                'id': history.id,
                'time': format_datetime(history.changed_at),
                'resource_name': config.resource_name,
                'resource_type': config.resource_type,
                'source': config.source,
                'severity': history.severity,
                'severity_badge': format_severity(history.severity),
                'change_count': change_count
            })
        
        # Get summary counts
        summary = {
            'total': total_items,
            'critical': ConfigurationHistory.query.filter_by(severity='critical').filter(
                ConfigurationHistory.changed_at >= start_date
            ).count(),
            'high': ConfigurationHistory.query.filter_by(severity='high').filter(
                ConfigurationHistory.changed_at >= start_date
            ).count(),
            'resources_affected': db.session.query(Configuration.id).join(
                ConfigurationHistory
            ).filter(
                ConfigurationHistory.changed_at >= start_date
            ).distinct().count()
        }
        
        # Pagination info
        pagination = {
            'current_page': page,
            'page_size': page_size,
            'total_pages': total_pages,
            'total_items': total_items,
            'start_index': (page - 1) * page_size + 1 if total_items > 0 else 0,
            'end_index': min(page * page_size, total_items)
        }
        
        return jsonify({
            'changes': changes,
            'summary': summary,
            'pagination': pagination
        })
        
    except Exception as e:
        logger.exception(f"Error fetching report data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/resource-types', methods=['GET'])
@login_required
def get_resource_types():
    """API endpoint for getting unique resource types"""
    try:
        # Get distinct resource types
        resource_types = db.session.query(Configuration.resource_type).distinct().all()
        resource_types = [r[0] for r in resource_types]
        
        return jsonify(sorted(resource_types))
        
    except Exception as e:
        logger.exception(f"Error fetching resource types: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    """API endpoint for getting all users (admin only)"""
    try:
        users = User.query.all()
        user_list = []
        
        for user in users:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'roles': [role.name for role in user.roles],
                'active': user.active,
                'last_login': format_datetime(user.last_login) if user.last_login else None,
                'microsoft_linked': bool(user.microsoft_id)
            }
            user_list.append(user_data)
        
        return jsonify(user_list)
        
    except Exception as e:
        logger.exception(f"Error fetching users: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/users/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'roles': [role.name for role in user.roles],
            'active': user.active,
            'last_login': format_datetime(user.last_login) if user.last_login else None,
            'microsoft_linked': bool(user.microsoft_id)
        }
        
        return jsonify(user_data)
        
    except Exception as e:
        logger.exception(f"Error fetching user {user_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    try:
        data = request.json
        
        # Validate required fields
        if not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Username, email and password are required'}), 400
        
        # Check if username or email already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already exists'}), 400
        
        # Create new user
        new_user = User(
            username=data['username'],
            email=data['email'],
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            active=data.get('active', True)
        )
        
        # Set password
        new_user.set_password(data['password'])
        
        # Add roles
        if 'roles' in data:
            for role_id in data['roles']:
                role = Role.query.get(role_id)
                if role:
                    new_user.roles.append(role)
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'id': new_user.id,
            'message': 'User created successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error creating user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.json
        
        # Validate required fields
        if not data.get('username') or not data.get('email'):
            return jsonify({'message': 'Username and email are required'}), 400
        
        # Check if username already exists (excluding this user)
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user and existing_user.id != user_id:
            return jsonify({'message': 'Username already exists'}), 400
        
        # Check if email already exists (excluding this user)
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user_id:
            return jsonify({'message': 'Email already exists'}), 400
        
        # Update user fields
        user.username = data['username']
        user.email = data['email']
        user.first_name = data.get('first_name')
        user.last_name = data.get('last_name')
        user.active = data.get('active', user.active)
        
        # Update password if provided
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        
        # Update roles
        if 'roles' in data:
            # Clear existing roles
            user.roles = []
            
            # Add new roles
            for role_id in data['roles']:
                role = Role.query.get(role_id)
                if role:
                    user.roles.append(role)
        
        db.session.commit()
        
        return jsonify({
            'id': user.id,
            'message': 'User updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating user {user_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Don't allow deleting yourself
        if user.id == current_user.id:
            return jsonify({'message': 'You cannot delete your own account'}), 400
        
        # Don't allow deleting the last admin user
        if user.has_role('admin'):
            admin_count = db.session.query(User).join(
                user_roles
            ).join(
                Role
            ).filter(
                Role.name == 'admin'
            ).count()
            
            if admin_count <= 1:
                return jsonify({'message': 'Cannot delete the last admin user'}), 400
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/roles', methods=['GET'])
@login_required
@admin_required
def get_roles():
    try:
        roles = Role.query.all()
        role_list = []
        
        for role in roles:
            # Count users with this role
            user_count = role.users.count()
            
            role_data = {
                'id': role.id,
                'name': role.name,
                'description': role.description,
                'user_count': user_count
            }
            role_list.append(role_data)
        
        return jsonify(role_list)
        
    except Exception as e:
        logger.exception(f"Error fetching roles: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/roles', methods=['POST'])
@login_required
@admin_required
def create_role():
    try:
        data = request.json
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'message': 'Role name is required'}), 400
        
        # Check if role already exists
        if Role.query.filter_by(name=data['name']).first():
            return jsonify({'message': 'Role already exists'}), 400
        
        # Create new role
        new_role = Role(
            name=data['name'],
            description=data.get('description')
        )
        
        db.session.add(new_role)
        db.session.commit()
        
        return jsonify({
            'id': new_role.id,
            'message': 'Role created successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error creating role: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/roles/<int:role_id>', methods=['PUT'])
@login_required
@admin_required
def update_role(role_id):
    try:
        role = Role.query.get_or_404(role_id)
        data = request.json
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'message': 'Role name is required'}), 400
        
        # Don't allow renaming admin role
        if role.name == 'admin' and data['name'] != 'admin':
            return jsonify({'message': 'Cannot rename the admin role'}), 400
        
        # Check if role name already exists (excluding this role)
        existing_role = Role.query.filter_by(name=data['name']).first()
        if existing_role and existing_role.id != role_id:
            return jsonify({'message': 'Role name already exists'}), 400
        
        # Update role
        role.name = data['name']
        role.description = data.get('description')
        
        db.session.commit()
        
        return jsonify({
            'id': role.id,
            'message': 'Role updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating role {role_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/roles/<int:role_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_role(role_id):
    try:
        role = Role.query.get_or_404(role_id)
        
        # Don't allow deleting built-in roles
        if role.name == 'admin':
            return jsonify({'message': 'Cannot delete the admin role'}), 400
        
        db.session.delete(role)
        db.session.commit()
        
        return jsonify({
            'message': 'Role deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error deleting role {role_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    try:
        data = request.json
        user = current_user
        
        # Update basic info
        if 'email' in data:
            # Check if email already exists (excluding this user)
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user.id:
                return jsonify({'message': 'Email already exists'}), 400
            
            user.email = data['email']
        
        if 'first_name' in data:
            user.first_name = data['first_name']
        
        if 'last_name' in data:
            user.last_name = data['last_name']
        
        # Handle password change
        if 'current_password' in data and 'new_password' in data:
            # Verify current password
            if not user.check_password(data['current_password']):
                return jsonify({'message': 'Current password is incorrect'}), 400
            
            # Set new password
            user.set_password(data['new_password'])
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/disconnect-microsoft', methods=['POST'])
@login_required
def disconnect_microsoft():
    try:
        user = current_user
        
        # Check if Microsoft account is linked
        if not user.microsoft_id:
            return jsonify({'message': 'No Microsoft account is linked'}), 400
        
        # Verify user has a password set
        if not user.password_hash:
            return jsonify({'message': 'You need to set a password before disconnecting Microsoft account'}), 400
        
        # Remove Microsoft account info
        user.microsoft_id = None
        user.access_token = None
        user.refresh_token = None
        user.token_expiry = None
        
        db.session.commit()
        
        return jsonify({
            'message': 'Microsoft account disconnected successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error disconnecting Microsoft account: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/settings', methods=['GET'])
@login_required
def get_settings():
    try:
        # Get settings from database
        stored_settings = Settings.get_settings()
        
        # Default settings
        settings = {
            'general': {
                'app_name': app.config.get('APP_NAME', 'Azure Drift Detector'),
                'timezone': 'UTC',
                'retention_days': 90,
                'debug_mode': app.debug
            },
            'azure': {
                'tenant_id_placeholder': '********',
                'client_id_placeholder': '********',
                'connection_status': 'Unknown'
            },
            'notifications': {
                'email_enabled': False,
                'email_recipients': '',
                'level': 'high',
                'webhook_enabled': False,
                'webhook_url': ''
            },
            'polling': {
                'interval_minutes': app.config.get('POLLING_INTERVAL', 30),
                'enabled': True,
                'last_poll_status': 'Never',
                'next_poll': 'Not scheduled'
            }
        }

        # Update with stored settings
        for key in stored_settings:
            if key in settings:
                settings[key].update(stored_settings[key])
        
        return jsonify(settings)
        
    except Exception as e:
        logger.exception(f"Error fetching settings: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/settings', methods=['POST'])
@login_required
@operator_required
def update_settings():
    try:
        data = request.json
        
        # Validate settings
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid settings format'}), 400
        
        # Update settings in database
        Settings.update_settings(data)
        
        # Update app configuration where applicable
        if 'general' in data:
            if 'app_name' in data['general']:
                app.config['APP_NAME'] = data['general']['app_name']
        
        if 'polling' in data:
            if 'interval_minutes' in data['polling']:
                app.config['POLLING_INTERVAL'] = data['polling']['interval_minutes']
        
        return jsonify({
            'message': 'Settings updated successfully',
            'settings': data
        })
        
    except Exception as e:
        logger.exception(f"Error updating settings: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/test-connection', methods=['GET'])
@login_required
@operator_required
def test_connection():
    try:
        # Check if Azure credentials are configured
        if not os.environ.get('AZURE_CLIENT_ID') or not os.environ.get('AZURE_CLIENT_SECRET'):
            return jsonify({
                'success': False,
                'message': 'Azure credentials not configured'
            })
        
        # Attempt to get a token
        from azure_poller import get_azure_token
        tokens = get_azure_token()
        
        if not tokens or not tokens.get('graph') or not tokens.get('azure'):
            return jsonify({
                'success': False,
                'message': 'Failed to obtain Azure access tokens'
            })
        
        return jsonify({
            'success': True,
            'message': 'Connection successful'
        })
        
    except Exception as e:
        logger.exception(f"Error testing connection: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@api_bp.route('/poll-now', methods=['POST'])
@login_required
@operator_required
def poll_now():
    try:
        # Trigger polling
        poll_azure_configurations()
        
        return jsonify({
            'success': True,
            'timestamp': format_datetime(datetime.utcnow()),
            'message': 'Manual polling completed successfully'
        })
        
    except Exception as e:
        logger.exception(f"Error during manual polling: {str(e)}")
        return jsonify({
            'success': False,
            'timestamp': format_datetime(datetime.utcnow()),
            'message': str(e)
        }), 500

@api_bp.route('/export/reports', methods=['GET'])
@login_required
def export_reports():
    try:
        export_format = request.args.get('format', 'csv')
        source = request.args.get('source', '')
        resource_type = request.args.get('resourceType', '')
        severity = request.args.get('severity', '')
        date_range = int(request.args.get('dateRange', 7))
        
        # Redirect to the export route
        from flask import redirect, url_for
        return redirect(url_for(
            'export_report',
            report_type='changes',
            format=export_format,
            source=source,
            resourceType=resource_type,
            severity=severity,
            dateRange=date_range
        ))
        
    except Exception as e:
        logger.exception(f"Error exporting report: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Register the blueprint with the app
app.register_blueprint(api_bp)
