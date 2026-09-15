"""
Access-control decorators. Kept separate from any single blueprint since
`admin_required` is used across the admin, labs, and analytics blueprints.
"""
from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("quizzes.home"))
        return view(*args, **kwargs)
    return wrapped
