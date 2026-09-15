# Data Engineering Labs

A hands-on companion to the Quizeers quiz app, covering the same 9-week
curriculum with runnable code instead of multiple-choice questions: ETL,
Unix/Linux, Python, data storage, relational & non-relational databases,
data warehousing/architecture, ingestion methods, Apache Spark, Apache
Kafka, Apache Airflow, batch/stream processing, and AWS/GCP/Azure.

Everything under `02_etl_pipeline/` through `08_batch_stream/` was actually
run and verified while building this repo (see "What's verified" below) —
this isn't just reference code, it's a working, if small, data platform.

## Layout

| Folder | Curriculum topic | What it demonstrates |
|---|---|---|
| `01_unix_shell/` | Unix/Linux | `ls`, `grep`, `cut`, `awk`, `sort \| uniq -c` piped together to inspect a raw data file from the command line |
| `02_etl_pipeline/` | ETL, Python | A real Extract → Transform → Load pipeline in Pandas; quarantines bad rows instead of silently dropping them |
| `03_databases/` | Relational & non-relational DBs, data warehousing | A star schema (fact + dimension tables) built from the ETL output, plus a document-store (NoSQL) demo with TinyDB for contrast |
| `04_spark/` | Apache Spark | The same ETL logic re-implemented with PySpark's DataFrame API, run in local cluster mode, writing partitioned Parquet |
| `05_kafka/` | Apache Kafka, ingestion methods | Real Kafka producer/consumer scripts for a live broker, plus a runnable broker-free simulation of topics/partitions/consumer groups |
| `06_airflow/` | Apache Airflow, orchestration | A real Airflow DAG (`extract >> transform >> load`) that runs the ETL pipeline on a schedule with retries |
| `07_cloud/` | AWS, GCP, Azure | Upload scripts for S3 / GCS / Blob Storage; the AWS one is verified against a mocked S3 bucket |
| `08_batch_stream/` | Batch vs. stream processing | Runs the same data through a batch job and a simulated stream job side by side to make the latency/consistency trade-off concrete |

## Quick start

Each folder is runnable on its own. From the repo root:

```bash
pip install -r requirements.txt

# 1. Unix/shell warm-up
bash 01_unix_shell/explore_data.sh

# 2. ETL pipeline (extract -> transform -> load into SQLite)
python3 02_etl_pipeline/pipeline.py

# 3. Star-schema warehouse + NoSQL contrast (run after step 2)
python3 03_databases/build_warehouse.py
python3 03_databases/nosql_demo.py

# 4. Spark job (requires Java; run after step 2's sample data exists)
pip install pyspark
python3 04_spark/spark_etl.py

# 5. Kafka: broker-free simulation (no setup needed)
python3 05_kafka/simulate_stream.py
# Kafka: real producer/consumer (requires a running broker, e.g. via Docker)
# python3 05_kafka/producer.py --bootstrap-servers localhost:9092
# python3 05_kafka/consumer.py --bootstrap-servers localhost:9092

# 6. Airflow DAG (isolated install recommended -- see 06_airflow/README.md)
# airflow standalone, then trigger the 'orders_etl' DAG from the UI

# 7. Cloud: AWS upload, tested against a mocked S3 bucket
pip install boto3 moto
python3 07_cloud/test_aws_s3_upload_with_moto.py

# 8. Batch vs. stream, side by side
python3 08_batch_stream/compare_batch_vs_stream.py
```

## What's verified vs. reference-only

Verified by actually running it while this repo was built:
- `01_unix_shell/explore_data.sh`
- `02_etl_pipeline/*` (full pipeline run, correct row quarantining)
- `03_databases/*` (star schema built, aggregation query correct; NoSQL demo run)
- `04_spark/spark_etl.py` (real PySpark job, local mode, matches pipeline results)
- `05_kafka/simulate_stream.py` (broker-free simulation, correct running totals)
- `06_airflow/dags/etl_dag.py` (ran through Airflow's real task engine end to end)
- `07_cloud/aws_s3_upload.py` (verified against a mocked S3 bucket via moto)
- `08_batch_stream/compare_batch_vs_stream.py`

Provided as reference code, not executable in this environment:
- `05_kafka/producer.py` / `consumer.py` — need a real Kafka broker
- `07_cloud/gcp_gcs_upload.py` / `azure_blob_upload.py` — need real GCP/Azure
  credentials (no free local emulator was available here); they follow the
  exact same structure as the tested AWS script

## Why this exists

A quiz can check whether you know what ETL, Spark, or Airflow *are*. It
can't show that you can build with them. This repo is meant to sit
alongside the Quizeers quiz content as the "I built this" evidence for
a data engineering portfolio or elective application.
