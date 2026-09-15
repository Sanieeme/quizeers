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

bp = Blueprint("labs", __name__, url_prefix="/labs")


@bp.route("")
@login_required
def labs_overview():
    return render_template("labs_overview.html", labs=LAB_CATALOG, weeks=WEEK_CATALOG)


@bp.route("/etl", methods=["GET", "POST"])
@login_required
def labs_etl_demo():
    """Live demo: actually runs the real ETL pipeline code from 02_etl_pipeline
    and shows the results in the browser, instead of just describing it."""
    result = None
    error = None
    if request.method == "POST":
        etl_dir = os.path.join(current_app.config["LABS_DIR"], "02_etl_pipeline")
        if etl_dir not in sys.path:
            sys.path.insert(0, etl_dir)
        try:
            from extract import extract_orders
            from transform import transform_orders

            raw = extract_orders(os.path.join(etl_dir, "sample_data", "orders_raw.csv"))
            clean, rejected = transform_orders(raw)
            result = {
                "raw_count": len(raw),
                "clean_count": len(clean),
                "rejected_count": len(rejected),
                "clean_rows": clean.to_dict(orient="records"),
                "rejected_rows": rejected.to_dict(orient="records"),
                "revenue_by_country": clean.groupby("country")["total_price"].sum().round(2).to_dict(),
            }
        except Exception as exc:  # surface pipeline errors in the UI rather than a 500 page
            error = str(exc)

    return render_template("labs_etl_demo.html", result=result, error=error)
