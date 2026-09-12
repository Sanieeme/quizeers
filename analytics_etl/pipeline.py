"""
pipeline.py -- runs the full analytics ETL: quizeers.db (operational)
-> aggregate -> analytics_warehouse.db (analytical).

Run manually with:  python3 analytics_etl/pipeline.py
In the app, the admin analytics dashboard has a button that calls run()
directly (see app.py's /admin/analytics route) so the pipeline can be
triggered on demand as new quiz attempts come in, in addition to being
schedulable via cron/Airflow for a periodic refresh.
"""
import os

from extract import extract_all
from transform import transform
from load import load

HERE = os.path.dirname(os.path.abspath(__file__))


def run(operational_db_path: str = None, warehouse_db_path: str = None) -> dict:
    operational_db_path = operational_db_path or os.path.join(HERE, "..", "quizeers.db")
    warehouse_db_path = warehouse_db_path or os.path.join(HERE, "analytics_warehouse.db")

    raw = extract_all(operational_db_path)
    aggregates = transform(raw)
    load(aggregates, warehouse_db_path)

    return {
        "raw_attempts": len(raw["attempts"]),
        "raw_question_attempts": len(raw["question_attempts"]),
        "warehouse_db_path": warehouse_db_path,
    }


if __name__ == "__main__":
    summary = run()
    print("\n[pipeline] summary:", summary)
