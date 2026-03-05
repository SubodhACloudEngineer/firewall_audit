"""config.py"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")
    UPLOAD_FOLDER = str(BASE_DIR / "uploads")
    REPORT_FOLDER = str(BASE_DIR / "reports")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024   # 50 MB upload limit
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
