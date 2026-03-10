"""app/__init__.py — Flask application factory"""
from pathlib import Path
from flask import Flask
from config import Config


def create_app(config=None):
    # Resolve static_folder to an absolute path so Flask always finds it
    # regardless of the working directory or WSL/Windows path quirks.
    app = Flask(
        __name__,
        static_folder=str(Path(__file__).resolve().parent / "static"),
        static_url_path="/static",
    )
    app.config.from_object(Config)
    if config:
        app.config.update(config)

    from app.routes import bp
    app.register_blueprint(bp)

    return app
