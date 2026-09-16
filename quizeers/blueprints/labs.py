"""
The Labs section: an overview of the labs/ folder's content, and a live
demo that actually executes the real ETL pipeline code. Kept separate from
admin.py even though admin users are the main audience, because "browse
educational content" is a different concern from "manage the quiz data."
"""
import os
import sys

from flask import Blueprint, render_template, request, current_app
from flask_login import login_required

from quizeers.lab_catalog import LAB_CATALOG, WEEK_CATALOG
from quizeers.models import Quiz

bp = Blueprint("labs", __name__, url_prefix="/labs")


def _with_related_quizzes(entries):
    """Resolve each entry's related_quiz_titles into real (id, title) Quiz
    rows, so the template can link straight to that quiz instead of just
    naming it. Returns new dicts -- never mutates the LAB_CATALOG /
    WEEK_CATALOG module-level constants."""
    quizzes_by_title = {
        q.title: q for q in Quiz.query.filter_by(is_deleted=False).all()
    }
    resolved = []
    for entry in entries:
        related = [
            quizzes_by_title[title]
            for title in entry.get("related_quiz_titles", [])
            if title in quizzes_by_title
        ]
        resolved.append({**entry, "related_quizzes": related})
    return resolved


@bp.route("")
@login_required
def labs_overview():
    return render_template(
        "labs_overview.html",
        labs=_with_related_quizzes(LAB_CATALOG),
        weeks=_with_related_quizzes(WEEK_CATALOG),
    )


@bp.route("/etl", methods=["GET", "POST"])
@login_required
def labs_etl_demo():
    """Live demo: actually runs the real ETL pipeline code from 02_etl_pipeline
    against a sample quiz-attempts log and shows the results in the browser,
    instead of just describing it."""
    result = None
    error = None
    if request.method == "POST":
        etl_dir = os.path.join(current_app.config["LABS_DIR"], "02_etl_pipeline")
        if etl_dir not in sys.path:
            sys.path.insert(0, etl_dir)
        try:
            from extract import extract_quiz_attempts
            from transform import transform_quiz_attempts

            raw = extract_quiz_attempts(os.path.join(etl_dir, "sample_data", "quiz_attempts_raw.csv"))
            clean, rejected = transform_quiz_attempts(raw)
            result = {
                "raw_count": len(raw),
                "clean_count": len(clean),
                "rejected_count": len(rejected),
                "clean_rows": clean.to_dict(orient="records"),
                "rejected_rows": rejected.to_dict(orient="records"),
                "score_by_category": clean.groupby("category")["score_percent"].mean().round(2).to_dict(),
            }
        except Exception as exc:  # surface pipeline errors in the UI rather than a 500 page
            error = str(exc)

    return render_template("labs_etl_demo.html", result=result, error=error)
