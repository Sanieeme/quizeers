from datetime import datetime
from airflow import DAG
from airflow.operators.bash import BashOperator

default_args = {
    'owner': 'airflow',
    'start_date': datetime(2026, 1, 1),
}

with DAG(
    dag_id='prototype_etl_pipeline',
    default_args=default_args,
    schedule_interval=None,
    catchup=False,
) as dag:

    extract = BashOperator(
        task_id='extract_dummy',
        bash_command='echo "extract: pull source data (SFTP / DB / stream)"'
    )

    transform = BashOperator(
        task_id='transform_spark',
        bash_command='spark-submit --master local[2] /workspace/prototype/spark/transform_job.py'
    )

    load = BashOperator(
        task_id='load_dummy',
        bash_command='echo "load: write to high-velocity store (ClickHouse/Druid/Pinot)"'
    )

    extract >> transform >> load
