import os
from flask import Blueprint, url_for, json, send_from_directory, current_app
from flask_swagger_ui import get_swaggerui_blueprint

SWAGGER_URL = '/api/docs'
API_URL = '/swagger.json'

swagger_ui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Azure Drift Detector API"
    }
)

swagger_bp = Blueprint('swagger', __name__)

@swagger_bp.route('/swagger.json')
def swagger_json():
    with open('static/swagger.json', 'r') as f:
        return current_app.response_class(
            f.read(),
            mimetype='application/json'
        )