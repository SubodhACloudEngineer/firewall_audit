"""app/__init__.py — Flask application factory"""
from flask import Flask
from config import Config


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config:
        app.config.update(config)

    from app.routes import bp
    app.register_blueprint(bp)

    return app
