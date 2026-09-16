# Data Engineering Labs

A hands-on companion to the Quizeers quiz app, covering the same 9-week
curriculum with runnable code instead of multiple-choice questions: ETL,
Unix/Linux, Python, data storage, relational & non-relational databases,
data warehousing/architecture, ingestion methods, Apache Spark, Apache
Kafka, Apache Airflow, batch/stream processing, and AWS/GCP/Azure.

Every lab runs on the same sample dataset -- a small, deliberately messy
log of **quiz attempts** (`02_etl_pipeline/sample_data/quiz_attempts_raw.csv`),
not generic e-commerce data. That's on purpose: this repo is the "I built
this" companion to Quizeers specifically, so the pipeline you're extracting,
transforming, loading, warehousing, streaming, and shipping to the cloud is
built from the same domain the quiz app itself runs on -- quiz titles,
categories, scores, attempt timestamps. It's the same shape of pipeline
`analytics_etl/` runs for real against the live `quizeers.db`, just worked
by hand on a small sample so every step is visible.

See "What's verified" below for exactly which scripts were actually run
against this dataset while building this repo.

## Layout

| Folder | Curriculum topic | What it demonstrates |
|---|---|---|
| `01_unix_shell/` | Unix/Linux | `ls`, `grep`, `cut`, `awk`, `sort \| uniq -c` piped together to inspect a raw quiz-attempts log from the command line |
| `02_etl_pipeline/` | ETL, Python | A real Extract → Transform → Load pipeline in Pandas on quiz-attempt records; quarantines bad rows instead of silently dropping them |
| `03_databases/` | Relational & non-relational DBs, data warehousing | A star schema (`dim_user`, `dim_quiz`, `dim_date`, `fact_attempt`) built from the ETL output, plus a document-store (NoSQL) demo of the same attempts with TinyDB for contrast |
| `04_spark/` | Apache Spark | The same quiz-attempts ETL logic re-implemented with PySpark's DataFrame API, run in local cluster mode, writing Parquet partitioned by quiz category |
| `05_kafka/` | Apache Kafka, ingestion methods | Real Kafka producer/consumer scripts that stream quiz-attempt events to a live broker, plus a runnable broker-free simulation computing a running average score |
| `06_airflow/` | Apache Airflow, orchestration | A real Airflow DAG (`extract >> transform >> load`) that runs the quiz-attempts ETL pipeline on a schedule with retries |
| `07_cloud/` | AWS, GCP, Azure | Upload scripts that ship the quiz-attempts Parquet output to S3 / GCS / Blob Storage; the AWS one is verified against a mocked S3 bucket |
| `08_batch_stream/` | Batch vs. stream processing | Runs the same quiz-attempts data through a batch job and a simulated stream job side by side to make the latency/consistency trade-off concrete |

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
# airflow standalone, then trigger the 'quiz_attempts_etl' DAG from the UI

# 7. Cloud: AWS upload, tested against a mocked S3 bucket
pip install boto3 moto
python3 07_cloud/test_aws_s3_upload_with_moto.py

# 8. Batch vs. stream, side by side
python3 08_batch_stream/compare_batch_vs_stream.py
```

## What's verified vs. reference-only

All labs were switched from a generic orders/e-commerce sample dataset to
the quiz-attempts dataset described above. Re-verified end to end, on the
new dataset, in the environment that made this change:
- `01_unix_shell/explore_data.sh` (correct counts per category, correct grep/awk output)
- `02_etl_pipeline/*` (10 raw → 7 clean / 3 rejected, correct quarantining, `score_percent` derived correctly)
- `03_databases/build_warehouse.py` (star schema built from the ETL output; average-score-by-category query correct)
- `05_kafka/simulate_stream.py` (broker-free simulation; correct running average score per category)
- `08_batch_stream/compare_batch_vs_stream.py` (batch and stream averages agree)

Rewritten to the same quiz-attempts dataset and pattern, but **not**
re-executed after the change (this environment has no network access to
install their dependencies -- `tinydb`, `pyspark`, `apache-airflow`,
`boto3`/`moto`, `google-cloud-storage`, `azure-storage-blob`). Each follows
the exact structure of the scripts above it depends on, so the logic should
carry over, but run these yourself before relying on them for a demo:
- `03_databases/nosql_demo.py` (needs `tinydb`)
- `04_spark/spark_etl.py` (needs `pyspark` + Java)
- `06_airflow/dags/etl_dag.py` (needs `apache-airflow`)
- `07_cloud/aws_s3_upload.py` / `test_aws_s3_upload_with_moto.py` (needs `boto3`/`moto`)

Provided as reference code, not executable in any sandbox:
- `05_kafka/producer.py` / `consumer.py` — need a real Kafka broker
- `07_cloud/gcp_gcs_upload.py` / `azure_blob_upload.py` — need real GCP/Azure
  credentials; they follow the exact same structure as the AWS script

## Why this exists

A quiz can check whether you know what ETL, Spark, or Airflow *are*. It
can't show that you can build with them. This repo is meant to sit
alongside the Quizeers quiz content as the "I built this" evidence for
a data engineering portfolio or elective application.
