"""
The application factory. This is the only module in the package that
knows how to assemble everything else -- config, extensions, models, and
blueprints -- into a working Flask app. Nothing else in the package
imports from here, which is what avoids circular imports.
"""
import os

from flask import Flask

from quizeers.config import Config
from quizeers.extensions import db, login_manager


def create_app(config_object=Config):
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
    )
    app.config.from_object(config_object)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    # Import models before registering blueprints, and before any
    # db.create_all() call, so SQLAlchemy knows about every table.
    from quizeers import models  # noqa: F401

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(models.User, int(user_id))

    from quizeers.blueprints.auth import bp as auth_bp
    from quizeers.blueprints.quizzes import bp as quizzes_bp
    from quizeers.blueprints.admin import bp as admin_bp
    from quizeers.blueprints.labs import bp as labs_bp
    from quizeers.blueprints.analytics import bp as analytics_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(quizzes_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(labs_bp)
    app.register_blueprint(analytics_bp)

    @app.cli.command("init-db")
    def init_db():
        """Create all tables. Usage: flask --app run.py init-db"""
        db.create_all()
        print("Database tables created.")

    return app
