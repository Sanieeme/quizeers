# Weeks 7-8 — Capstone Project

A real, end-to-end, multi-source pipeline: ingest from **Postgres (via CDC)**
and **SFTP**, transform with **dbt**, serve via a **REST API**, with a
**high-velocity store (Redis)** for real-time queries alongside a
**batch-processed warehouse (DuckDB)** for analytics.

## Architecture

```
Postgres (inventory)      SFTP server (daily_orders_extract.csv)
       |                              |
   trigger-based CDC            paramiko download
   (cdc/setup_cdc_source.py)    (ingestion/sftp_ingest.py)
       |                              |
   cdc_log table                 downloaded/*.csv
       |                              |
   apply_cdc_to_redis.py    load_raw_sources.py (also pulls the
       |                     original batch ETL's warehouse.db)
       v                              v
     Redis                       DuckDB (raw tables)
  (real-time store)                   |
       |                          dbt run / dbt test
       |                     (staging models -> mart models)
       |                              |
       +----------> api/serve.py <----+
                  (Flask REST API)
                  /api/inventory/<sku>  <- Redis (real-time)
                  /api/revenue          <- DuckDB mart (batch)
                  /api/orders           <- DuckDB mart (batch)

Orchestrated by dags/capstone_dag.py:
  [ingest_sftp, apply_cdc_to_redis] >> load_raw_sources_to_duckdb >> dbt_run >> dbt_test
```

## Why this design

- **Two ingestion paths on purpose.** SFTP (file drop, the legacy-system
  pattern from Week 6's case study) and CDC (continuous change stream from
  a live database) are genuinely different integration problems, and a
  real capstone-scale pipeline has to handle both without one polluting
  the other's code.
- **CDC, not full-table reload.** `cdc/setup_cdc_source.py` captures every
  INSERT/UPDATE/DELETE as a discrete, ordered event via a Postgres
  trigger — the same *outcome* Debezium gets from reading the WAL via
  logical replication, without needing a Kafka Connect worker (not
  installable in this sandbox). `cdc/apply_cdc_to_redis.py` is a real
  CDC consumer: it checkpoints by `log_id` so re-running it only applies
  new changes, never replays the whole log.
- **dbt owns the "T" in ELT.** Raw data from both sources lands untouched
  in DuckDB (`dbt_project/load_raw_sources.py`), then `dbt_project/models/`
  does all cleaning and joining as SQL — the same ELT pattern from Week
  4, with a real transformation tool instead of one hand-written query.
- **Two serving speeds, matched to two data shapes.** `/api/inventory/<sku>`
  reads Redis for point lookups kept current by CDC (sub-millisecond,
  no aggregation). `/api/revenue` and `/api/orders` read the dbt-built
  DuckDB mart (aggregation-friendly, refreshed on the dbt run cadence).
  This is the "high-velocity store for real-time queries" requirement,
  implemented as an actual architectural split rather than one database
  trying to do both jobs well.

## What's genuinely tested vs. reference-only

Everything above was **run end-to-end** in this sandbox, including through
Airflow's real task engine (`airflow tasks test capstone_pipeline <task>`
for all 6 tasks — ingest_sftp, apply_cdc_to_redis,
load_raw_sources_to_duckdb, dbt_run, dbt_test — all passed):

| Piece | Real technology used | Verified how |
|---|---|---|
| CDC | Real PostgreSQL + trigger | 6 real INSERT/UPDATE/DELETE events captured correctly |
| SFTP ingestion | Real OpenSSH server + paramiko | File downloaded, marked processed; idempotent re-run confirmed |
| High-velocity store | Real Redis | Point lookups correct; deleted SKU correctly absent |
| Transformation | Real dbt (dbt-duckdb adapter) | 5 models built, 6 dbt tests passed |
| Served API | Real Flask app | All 4 endpoints hit with curl, correct data returned |
| Orchestration | Real Apache Airflow | All 6 DAG tasks run via `airflow tasks test`, all succeeded |

**Reference-only / confirmed infeasible in this sandbox (attempted, not assumed):**
- **Debezium + Kafka Connect**: the trigger-based CDC above captures the
  same information a real Debezium connector would, but Debezium itself
  needs a Kafka Connect worker and its packages are distributed via Maven
  Central/Docker, neither reachable through this sandbox's restricted
  network. In a real deployment, swap `cdc/setup_cdc_source.py`'s trigger
  for Postgres's native logical replication slot and point a Debezium
  connector at it — the downstream consumer logic in
  `apply_cdc_to_redis.py` would barely change (read from a Kafka topic
  instead of polling `cdc_log`).
- **A real Kafka/Redpanda broker**: genuinely attempted, not just assumed
  unavailable — Redpanda's GitHub releases were checked directly (via the
  release page's asset list) and only publish the `rpk` client CLI, not
  the actual broker binary; the broker itself ships via Redpanda's own
  package repository and Docker images, neither reachable here. Apache
  Kafka doesn't publish GitHub release binaries at all (ASF distributes
  via its own mirror network, also outside this sandbox's allowlist).
  `../../05_kafka/simulate_stream.py` remains the broker-free stand-in.

## Running it yourself

```bash
# 1. Set up the CDC source and simulate some source-system activity
python3 cdc/setup_cdc_source.py

# 2. Apply the change log to Redis
python3 cdc/apply_cdc_to_redis.py

# 3. Ingest the SFTP file (requires a local SFTP/SSH server -- see this
#    folder's setup notes, or point SFTP_HOST/USER/PASS at a real server)
python3 ingestion/sftp_ingest.py

# 4. Load everything raw into DuckDB, then transform with dbt
cd dbt_project
python3 load_raw_sources.py
dbt run
dbt test

# 5. Serve it
cd ../api
python3 serve.py
curl http://localhost:5050/api/inventory/SKU-001
curl http://localhost:5050/api/revenue

# Or orchestrate all of the above with Airflow (see ../../06_airflow/README.md
# for the isolated-venv setup this needs):
airflow tasks test capstone_pipeline ingest_sftp 2026-01-01
airflow tasks test capstone_pipeline apply_cdc_to_redis 2026-01-01
airflow tasks test capstone_pipeline load_raw_sources_to_duckdb 2026-01-01
airflow tasks test capstone_pipeline dbt_run 2026-01-01
airflow tasks test capstone_pipeline dbt_test 2026-01-01
```
