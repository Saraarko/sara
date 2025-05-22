# === app/__init__.py ===
from flask import Flask
from flask_cors import CORS
import os
from dotenv import load_dotenv

def create_app():
    load_dotenv()
    app = Flask(__name__)
    CORS(app)

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret')

    from .auth import auth_bp
    app.register_blueprint(auth_bp)

    return app
