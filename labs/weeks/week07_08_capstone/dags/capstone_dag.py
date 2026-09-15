"""
Capstone — Airflow DAG orchestrating the full multi-source pipeline:

  ingest_sftp  -----\
                      >--> load_raw_sources_to_duckdb --> dbt_run --> dbt_test
  apply_cdc_to_redis /

The two ingestion paths (file-based SFTP, and CDC from Postgres) run in
parallel since they're independent, then converge into the DuckDB load
step that both dbt models depend on. This mirrors real capstone-style
orchestration: different sources have different shapes and cadences, but
the DAG still expresses a single coherent dependency graph.

To run for real, follow the same isolated-venv approach as
../../06_airflow/README.md (Airflow's pins conflict with this repo's other
dependencies).
"""
import os
import sys
import subprocess
from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator

CAPSTONE_DIR = os.path.join(os.path.dirname(__file__), "..")

default_args = {
    "owner": "data-engineering-labs",
    "retries": 2,
    "retry_delay": timedelta(minutes=2),
}

with DAG(
    dag_id="capstone_pipeline",
    description="Multi-source capstone: SFTP + CDC ingestion, dbt transformation, served via REST API.",
    default_args=default_args,
    schedule="@hourly",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    tags=["capstone", "cdc", "dbt", "sftp"],
) as dag:

    def _ingest_sftp(**context):
        sys.path.insert(0, os.path.join(CAPSTONE_DIR, "ingestion"))
        from sftp_ingest import ingest
        files = ingest()
        context["ti"].xcom_push(key="files_ingested", value=len(files))

    def _apply_cdc(**context):
        sys.path.insert(0, os.path.join(CAPSTONE_DIR, "cdc"))
        from apply_cdc_to_redis import apply_changes
        n = apply_changes()
        context["ti"].xcom_push(key="changes_applied", value=n)

    def _load_raw_sources(**context):
        sys.path.insert(0, os.path.join(CAPSTONE_DIR, "dbt_project"))
        import duckdb
        import load_raw_sources
        con = duckdb.connect(os.path.join(CAPSTONE_DIR, "dbt_project", "capstone.duckdb"))
        load_raw_sources.load_sftp_orders(con)
        load_raw_sources.load_inventory_from_postgres(con)
        load_raw_sources.load_batch_orders_from_etl(con)
        con.close()

    ingest_sftp = PythonOperator(task_id="ingest_sftp", python_callable=_ingest_sftp)
    apply_cdc = PythonOperator(task_id="apply_cdc_to_redis", python_callable=_apply_cdc)
    load_raw = PythonOperator(task_id="load_raw_sources_to_duckdb", python_callable=_load_raw_sources)

    dbt_run = BashOperator(
        task_id="dbt_run",
        cwd=os.path.join(CAPSTONE_DIR, "dbt_project"),
        bash_command="dbt run",
    )
    dbt_test = BashOperator(
        task_id="dbt_test",
        cwd=os.path.join(CAPSTONE_DIR, "dbt_project"),
        bash_command="dbt test",
    )

    [ingest_sftp, apply_cdc] >> load_raw >> dbt_run >> dbt_test
