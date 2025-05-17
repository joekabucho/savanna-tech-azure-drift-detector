from app import app, db
import auth

from api import api_bp
from swagger import swagger_ui_blueprint, swagger_bp, SWAGGER_URL

app.register_blueprint(api_bp, name='api_v1')
app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)
app.register_blueprint(swagger_bp)

with app.app_context():
    db.create_all()
    
    if hasattr(auth, 'create_default_roles'):
        auth.create_default_roles()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
