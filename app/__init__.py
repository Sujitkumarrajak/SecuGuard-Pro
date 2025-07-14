from flask import Flask
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)  # ✅ create limiter

def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'your-secret-key'

    jwt.init_app(app)
    limiter.init_app(app)

    from app.routes.scan import scan_bp
    app.register_blueprint(scan_bp, url_prefix="/api")

    from app.routes.auth import auth_bp  # ✅ import auth_bp
    app.register_blueprint(auth_bp)     # ✅ register it

    return app
