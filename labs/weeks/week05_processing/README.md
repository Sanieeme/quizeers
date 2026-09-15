# Week 5 — Data Processing

## Big data: Volume, Velocity, Variety

Illustrated across the tools below rather than just defined: Spark handles
**Volume** (distributes a dataset across executors), Kafka/streaming
handles **Velocity** (processes events as they arrive instead of waiting
for a batch window), and the NoSQL demos in Week 3 handle **Variety**
(documents with different shapes in the same collection).

## Pandas, Apache Spark, Apache Beam, Kafka

- **Pandas**: `../../02_etl_pipeline/` — the baseline ETL implementation.
- **Apache Spark**: `../../04_spark/spark_etl.py` — the same logic
  re-implemented with Spark's DataFrame API, run in local cluster mode.
- **Apache Beam**: `beam_pipeline.py` — **run with the DirectRunner** in
  this sandbox. Same logic again, expressed as Beam transforms
  (`ParDo`/`Map`/`CombinePerKey`) instead of a DataFrame API. Beam's whole
  premise is portability: this exact pipeline code can target Dataflow,
  Flink, or Spark as the execution engine just by changing the runner —
  the transform graph doesn't change. Verified output matches Spark and
  Pandas exactly: 7 valid rows, 3 rejected, same revenue-by-country totals
  (South Africa 161.11, USA 41.50, Kenya 12.75).
- **Kafka**: `../../05_kafka/` — producer/consumer code plus a runnable
  broker-free simulation of streaming ingestion.

## Workflow orchestration: Apache Airflow, DAGs

`../../06_airflow/dags/etl_dag.py` — a real DAG (`extract >> transform >>
load`), run end-to-end through Airflow's actual task engine (see that
folder's README for how it was verified).

## Batch vs. stream for different use cases

`../../08_batch_stream/compare_batch_vs_stream.py` — runs the same data
through a batch job and a stream job side by side, verified.
