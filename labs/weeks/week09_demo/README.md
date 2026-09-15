# Week 9 — Demo and Presentation

This week isn't code — it's a live demo of the pipeline from source to API
output, followed by defending the architecture to reviewers. This is a
template for that, filled in against the actual capstone built in
`../week07_08_capstone/`, meant to be adapted rather than read verbatim.

## Suggested live demo script

1. Show the source systems: the `inventory` table in Postgres, and the
   `daily_orders_extract.csv` sitting in the SFTP landing zone.
2. Make a live change to `inventory` (an `UPDATE`) and show the `cdc_log`
   table capturing it immediately.
3. Run `apply_cdc_to_redis.py` and show the updated value now in Redis —
   then hit `/api/inventory/<sku>` and show the API returning it.
4. Run the SFTP ingestion and the dbt pipeline, then hit `/api/revenue`
   and `/api/orders` and show the SFTP-sourced orders sitting alongside
   the original batch-ETL orders in one unified result.
5. Show the Airflow UI (or `airflow tasks test` output) proving the whole
   thing is one orchestrated DAG, not a set of scripts run by hand.

## Questions reviewers are likely to ask, and how to answer them honestly

**"Why trigger-based CDC instead of Debezium?"**
Be direct: Debezium needs a Kafka Connect worker, which wasn't available
in the build environment. The trigger captures the same before/after/op
information Debezium would extract from the WAL — the difference is
*how* the change is captured, not *what* is captured. In production,
you'd want Debezium specifically because triggers add write-path latency
and coupling to the source database that WAL-based CDC avoids.

**"Why Redis instead of a real distributed cache like a Redis Cluster or DynamoDB Accelerator?"**
Scale: a single Redis instance is fine for a demo's dozens of SKUs, but a
production high-velocity store needs to handle the actual read/write
volume and availability requirements — that's a capacity-planning
decision, not a technology swap.

**"What happens if the SFTP file arrives twice, or a CDC event is applied twice?"**
SFTP: the ingestion script archives processed files with a timestamp
suffix so the same filename can safely reappear, but doesn't currently
deduplicate by file *content* — a genuine gap worth naming, not hiding.
CDC: `apply_cdc_to_redis.py`'s checkpoint by `log_id` makes re-application
safe (idempotent) as long as the checkpoint file itself doesn't get lost —
which is itself a fragility worth naming (a real system would checkpoint
in a transactional store, not a local text file).

**"How would this scale to real capstone-brief volume (millions of events)?"**
Name the bottlenecks honestly: the trigger-based CDC would add write
latency to the source table under high write volume (a real reason to
prefer WAL-based CDC at scale); a single-file SQLite/DuckDB warehouse
would need to become a real distributed warehouse (BigQuery/Snowflake);
and the Flask dev server explicitly says in its own output that it's not
for production — a real deployment needs a WSGI server behind a load
balancer.

## The core presentation principle

Defend what was actually built and tested, and be equally clear about
what's a deliberate simplification for the sandbox this was built in vs.
what would need to change for production scale. Reviewers generally trust
"here's what I verified, and here's exactly why the real version would
differ" far more than a claim that everything here is production-ready.
