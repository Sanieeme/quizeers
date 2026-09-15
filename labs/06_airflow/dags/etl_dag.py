"""
Airflow DAG that orchestrates the exact same Extract -> Transform -> Load
pipeline as 02_etl_pipeline/pipeline.py, wired up with scheduling, retries,
and task dependencies.

To run for real:
  1. pip install apache-airflow
  2. export AIRFLOW_HOME=~/airflow
  3. Copy this file (and the 02_etl_pipeline/ package it imports from) into
     $AIRFLOW_HOME/dags/
  4. airflow standalone   # starts the scheduler + webserver + creates an admin user
  5. Open http://localhost:8080, unpause the 'orders_etl' DAG, and trigger it.
"""
import os
import sys
from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.python import PythonOperator

# Make the sibling 02_etl_pipeline package importable from within the DAG.
ETL_PKG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "02_etl_pipeline")
sys.path.append(os.path.abspath(ETL_PKG_DIR))

default_args = {
    "owner": "data-engineering-labs",
    "retries": 2,
    "retry_delay": timedelta(minutes=2),
}

with DAG(
    dag_id="orders_etl",
    description="Extract, transform, and load daily order data into the warehouse.",
    default_args=default_args,
    schedule="@daily",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    tags=["etl", "orders"],
) as dag:

    # Intermediate hand-off between tasks uses pickle files rather than XCom/JSON:
    # XCom is meant for small values (it's stored in the metadata DB), and JSON
    # round-tripping a DataFrame loses exact dtypes/NaN-vs-None distinctions —
    # pickle preserves the DataFrame exactly as transform.py expects it.
    def _extract(**context):
        from extract import extract_orders
        raw = extract_orders(os.path.join(ETL_PKG_DIR, "sample_data", "orders_raw.csv"))
        context["ti"].xcom_push(key="raw_row_count", value=len(raw))
        raw.to_pickle(os.path.join(ETL_PKG_DIR, "output", "_raw.pkl"))

    def _transform(**context):
        import pandas as pd
        from transform import transform_orders
        raw = pd.read_pickle(os.path.join(ETL_PKG_DIR, "output", "_raw.pkl"))
        clean, rejected = transform_orders(raw)
        clean.to_pickle(os.path.join(ETL_PKG_DIR, "output", "_clean.pkl"))
        rejected.to_pickle(os.path.join(ETL_PKG_DIR, "output", "_rejected.pkl"))
        context["ti"].xcom_push(key="clean_row_count", value=len(clean))
        context["ti"].xcom_push(key="rejected_row_count", value=len(rejected))

    def _load(**context):
        import pandas as pd
        from load import load_orders
        clean = pd.read_pickle(os.path.join(ETL_PKG_DIR, "output", "_clean.pkl"))
        rejected = pd.read_pickle(os.path.join(ETL_PKG_DIR, "output", "_rejected.pkl"))
        load_orders(clean, rejected, os.path.join(ETL_PKG_DIR, "output", "warehouse.db"))

    extract_task = PythonOperator(task_id="extract", python_callable=_extract)
    transform_task = PythonOperator(task_id="transform", python_callable=_transform)
    load_task = PythonOperator(task_id="load", python_callable=_load)

    # Task dependency graph — the DAG this file is named for
    extract_task >> transform_task >> load_task
