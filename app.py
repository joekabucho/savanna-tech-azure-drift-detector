import os
import logging
from flask import Flask, redirect, url_for, flash, render_template, request
from flask_login import LoginManager, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler
from flask_migrate import Migrate
import atexit

logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres"):
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    logger.info("Using PostgreSQL database")
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
    logger.info("Using SQLite database")

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = 'Please log in to access this page.'

from models import User, Role, UserRole, Configuration, ConfigurationHistory, SigningLog
import auth
import routes
from azure_poller import poll_azure_configurations

scheduler = BackgroundScheduler()
scheduler.add_job(func=poll_azure_configurations, trigger="interval", minutes=30)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    from routes import get_dashboard_stats
    stats = get_dashboard_stats()
    return render_template('dashboard.html', 
                          total_resources=stats['total_resources'],
                          critical_changes=stats['critical_changes'],
                          recent_changes=stats['recent_changes'],
                          signin_events=stats['signin_events'])

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('base.html', error="404 - Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('base.html', error="500 - Internal server error"), 500
