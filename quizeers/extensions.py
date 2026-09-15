"""
Flask extension instances, created here without an app bound yet.

Keeping these separate from both models.py and __init__.py (the app
factory) is what breaks the circular-import problem: models.py needs `db`,
blueprints need both `db` and `login_manager`, and the app factory needs
to call `db.init_app(app)` -- if any of those lived in the same module
that imports the others, you'd get an import cycle.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
