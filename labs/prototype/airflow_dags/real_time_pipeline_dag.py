from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.bash import BashOperator

default_args = {
    'owner': 'data-engineering-team',
    'depends_on_past': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
}

with DAG(
    dag_id='real_time_data_pipeline',
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule_interval=None,
    catchup=False,
) as dag:

    register_debezium = BashOperator(
        task_id='register_debezium_connector',
        bash_command=(
            "curl -X POST -H 'Content-Type: application/json' --data @/opt/airflow/dags/prototype/debezium/mysql-connector.json "
            "http://debezium:8083/connectors || echo 'connector may already exist'"
        ),
    )

    run_batch_spark = BashOperator(
        task_id='run_spark_batch',
        bash_command=(
            "spark-submit --master local[2] /opt/airflow/dags/prototype/spark/batch_job.py || true"
        ),
    )

    start_streaming = BashOperator(
        task_id='start_spark_stream',
        bash_command=(
            "nohup spark-submit --master local[2] /opt/airflow/dags/prototype/spark/streaming_job.py > /tmp/stream.log 2>&1 &"
        ),
    )

    register_debezium >> run_batch_spark >> start_streaming
