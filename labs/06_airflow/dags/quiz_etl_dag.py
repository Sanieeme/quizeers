"""Prototype Airflow DAG to run Spark ETL and downstream tasks.

Place this in an Airflow `dags/` folder for testing. Tasks are placeholders
and should be replaced with cluster submission commands in production.
"""
from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.bash import BashOperator

default_args = {
    'owner': 'data-team',
    'depends_on_past': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
}

with DAG(
    dag_id='quiz_etl_pipeline',
    default_args=default_args,
    description='Prototype DAG: run Spark ETL and downstream tasks',
    schedule_interval='@hourly',
    start_date=datetime(2026, 1, 1),
    catchup=False,
) as dag:

    # Run the PySpark ETL locally (adjust to your cluster submission in prod)
    run_spark_etl = BashOperator(
        task_id='run_spark_etl',
        bash_command='python3 {{ params.project_root }}/labs/04_spark/spark_etl.py',
        params={'project_root': '/Users/zwanganetshidzivhani/shonisani/testing/quizeers'},
    )

    # Placeholder: a task that would load results to the high-velocity store
    load_to_clickhouse = BashOperator(
        task_id='load_to_clickhouse',
        bash_command='echo "Load Parquet -> ClickHouse (prototype)"'
    )

    # Placeholder: notify or snapshot
    notify = BashOperator(
        task_id='notify',
        bash_command='echo "ETL finished"'
    )

    run_spark_etl >> load_to_clickhouse >> notify
