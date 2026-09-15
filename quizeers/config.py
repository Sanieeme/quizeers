"""
Configuration. Kept separate from the app factory so config can be swapped
(e.g. a TestConfig with an in-memory database) without touching app setup
code at all.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "quizeers.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    LABS_DIR = os.path.join(BASE_DIR, "labs")
    ANALYTICS_DIR = os.path.join(BASE_DIR, "analytics_etl")
    OPERATIONAL_DB_PATH = os.path.join(BASE_DIR, "quizeers.db")


class TestConfig(Config):
    """An in-memory database for fast, isolated tests -- nothing currently
    uses this, but it's the reason config lives in its own module rather
    than as constants scattered through the app factory."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
