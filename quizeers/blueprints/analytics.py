"""
The learning-analytics dashboard, powered by the real ETL pipeline in
analytics_etl/. Kept as its own blueprint rather than folded into admin.py
because it has a genuinely different job: admin.py manages quiz *content*,
this presents *insights derived from* quiz activity via its own pipeline.
"""
import os
import sys

from flask import Blueprint, render_template, request, current_app

from quizeers.decorators import admin_required

bp = Blueprint("analytics", __name__, url_prefix="/admin/analytics")


@bp.route("", methods=["GET", "POST"])
@admin_required
def admin_analytics():
    """Real ETL in production use: aggregates raw quiz-attempt data from the
    operational database (quizeers.db) into a separate analytics warehouse
    (analytics_etl/analytics_warehouse.db), then renders the results.

    GET renders whatever is currently in the warehouse (possibly stale).
    POST re-runs the ETL pipeline first, so the dashboard reflects the very
    latest attempts, then renders the refreshed warehouse.
    """
    analytics_dir = current_app.config["ANALYTICS_DIR"]
    if analytics_dir not in sys.path:
        sys.path.insert(0, analytics_dir)

    from load import read_table

    warehouse_path = os.path.join(analytics_dir, "analytics_warehouse.db")
    ran_pipeline = False
    pipeline_summary = None
    error = None

    if request.method == "POST":
        try:
            import pipeline as analytics_pipeline
            pipeline_summary = analytics_pipeline.run(
                operational_db_path=current_app.config["OPERATIONAL_DB_PATH"],
                warehouse_db_path=warehouse_path,
            )
            ran_pipeline = True
        except Exception as exc:
            error = str(exc)

    tables = {
        name: read_table(warehouse_path, name).to_dict(orient="records")
        for name in [
            "quiz_performance", "question_difficulty",
            "category_performance", "score_trend", "user_progress",
        ]
    }

    return render_template(
        "admin_analytics.html",
        tables=tables,
        ran_pipeline=ran_pipeline,
        pipeline_summary=pipeline_summary,
        error=error,
    )
