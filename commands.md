# Setup
pip install -r requirements.txt
python seed.py
python run.py

# Week 1
cd labs/01_unix_shell && bash explore_data.sh
cd ../02_etl_pipeline && python3 pipeline.py

# Week 2
cd ../weeks/week02_storage && python3 compare_file_formats.py

# Week 3
cd ../week03_dbms && python3 normalization_demo.py
python3 mysql_demo.py

# Week 4-5
cd ../week04_architecture_ingestion && python3 rest_api_ingestion.py
cd ../../04_spark && python3 spark_etl.py

# Week 6
cd ../weeks/week06_governance && python3 data_quality_checks.py

# App analytics: browser to http://127.0.0.1:5000/admin/analytics

# Capstone
cd labs/weeks/week07_08_capstone/cdc
python3 setup_cdc_source.py
python3 apply_cdc_to_redis.py
cd ../ingestion && python3 sftp_ingest.py
cd ../dbt_project && python3 load_raw_sources.py && dbt run && dbt test
cd ../api && python3 serve.py &
curl http://localhost:5050/api/question/Q-101
curl http://localhost:5050/api/quiz-performance

# Airflow
export AIRFLOW_HOME=~/airflow_home_capstone
export AIRFLOW__CORE__DAGS_FOLDER=$(pwd)/../dags
airflow tasks test capstone_pipeline dbt_test 2026-01-01

# Cloud
cd ../../../07_cloud && python3 test_aws_s3_upload_with_moto.py