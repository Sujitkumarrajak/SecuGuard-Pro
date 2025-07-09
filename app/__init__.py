
from flask import Flask
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'your-secret-key'
    jwt = JWTManager(app)

    return app