# Week 4 — Data Architecture and Ingestion

## Data warehouses (BigQuery, Snowflake) vs. data lakes (S3, ADLS)

- **Warehouse**: structured, schema-enforced, optimized for SQL analytics.
  `../../03_databases/warehouse_schema.sql` + `build_warehouse.py` build a
  real star-schema warehouse (tested, in the original labs set).
  `bigquery_reference.py` here shows the same load pattern targeting a real
  managed warehouse — reference code (no GCP credentials in this sandbox),
  following the exact structure already verified for AWS S3 in
  `../../07_cloud/aws_s3_upload.py`.
- **Lake**: raw, schema-on-read, holds any format at any structure level.
  `../../07_cloud/aws_s3_upload.py` (verified against mocked S3) plays this
  role — Parquet files sitting in object storage with no enforced schema
  until something reads them.
- **Snowflake** specifically: same warehouse role as BigQuery, with its own
  Python connector (`snowflake-connector-python`, installed here) — the
  load/query pattern in `bigquery_reference.py` maps over directly, just
  swapping the client.

## ETL vs. EL vs. ELT

`etl_vs_el_vs_elt.py` — **run and verified**. Implements the same job
three ways against real SQLite:
- **ETL**: 8 clean rows produced by transforming in Python before loading.
- **EL**: all 10 raw rows loaded completely untouched, bad data included.
- **ELT**: the same raw load, then an actual `CREATE TABLE ... AS SELECT`
  transformation query run *inside* the destination database — the same
  mechanic a dbt model or a BigQuery scheduled query uses.

## Batch and stream ingestion

Already covered in the original labs set:
`../../05_kafka/` (streaming ingestion) and `../../08_batch_stream/` (the
batch vs. stream comparison, run side by side on the same data).

## Reading from REST APIs (`requests`, `urllib`)

`rest_api_ingestion.py` — **run against the real GitHub REST API**
(`api.github.com`), not a mock. Demonstrates the extract-transform split
for API data, and — because this sandbox's shared IP is frequently
rate-limited by GitHub's public API — includes real exponential-backoff
retry logic for HTTP 403 rate-limit responses and 5xx server errors. In
the run captured for this repo, one request hit a rate limit, retried
after a 2s backoff, and succeeded; all three repos were ultimately
ingested successfully.
