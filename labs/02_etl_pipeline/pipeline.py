"""
pipeline.py — runs the full Extract -> Transform -> Load pipeline end to end.

This is intentionally the same three function calls that 06_airflow/dags/etl_dag.py
wires up as an Airflow DAG — the business logic doesn't change when you add an
orchestrator, only who calls it and when.
"""
import os
import sys

from extract import extract_orders
from transform import transform_orders
from load import load_orders

HERE = os.path.dirname(os.path.abspath(__file__))


def run(raw_path: str = None, db_path: str = None) -> dict:
    raw_path = raw_path or os.path.join(HERE, "sample_data", "orders_raw.csv")
    db_path = db_path or os.path.join(HERE, "output", "warehouse.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    raw = extract_orders(raw_path)
    clean, rejected = transform_orders(raw)
    load_orders(clean, rejected, db_path)

    return {
        "raw_rows": len(raw),
        "clean_rows": len(clean),
        "rejected_rows": len(rejected),
        "db_path": db_path,
    }


if __name__ == "__main__":
    summary = run()
    print("\n[pipeline] summary:", summary)
    sys.exit(0)
