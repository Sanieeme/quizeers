"""
Capstone — REST API serving pipeline output, the final "source to API
output" requirement.

Two genuinely different serving paths, on purpose:
- /api/inventory/<sku>: reads from Redis, the high-velocity store the CDC
  pipeline (../cdc/apply_cdc_to_redis.py) keeps up to date in near-real
  time. Point lookups by key, sub-millisecond.
- /api/revenue and /api/orders: read from the dbt-built DuckDB mart
  (../dbt_project/capstone.duckdb), the batch-processed, analytics-shaped
  output. Aggregation-friendly, refreshed on the dbt run schedule rather
  than instantly.

This split -- fast point-lookups from a key-value store, and richer
aggregation from a warehouse -- is exactly the two-speed architecture the
capstone brief describes (a high-velocity store for real-time queries,
plus multi-source batch/stream processing feeding a queryable mart).
"""
import json
import os

import duckdb
import redis
from flask import Flask, jsonify, abort

app = Flask(__name__)

HERE = os.path.dirname(os.path.abspath(__file__))
DUCKDB_PATH = os.path.join(HERE, "..", "dbt_project", "capstone.duckdb")


def get_redis():
    return redis.Redis(host="localhost", port=6379, decode_responses=True)


def get_duckdb():
    # read_only=True: the API serves the mart, it never writes to it --
    # writes only happen through the dbt run / CDC pipelines.
    return duckdb.connect(DUCKDB_PATH, read_only=True)


@app.route("/api/inventory/<sku>")
def get_inventory(sku):
    """Real-time path: served straight from Redis, kept current by CDC."""
    r = get_redis()
    raw = r.get(f"inventory:{sku}")
    if raw is None:
        abort(404, description=f"No inventory record for SKU '{sku}' (may have been deleted, or never existed)")
    return jsonify(json.loads(raw))


@app.route("/api/revenue")
def get_revenue():
    """Batch/analytical path: served from the dbt-built mart."""
    con = get_duckdb()
    rows = con.execute("SELECT country, source_system, revenue, order_count FROM mart_revenue_by_country").fetchall()
    con.close()
    return jsonify([
        {"country": r[0], "source_system": r[1], "revenue": r[2], "order_count": r[3]}
        for r in rows
    ])


@app.route("/api/orders")
def get_orders():
    """The unified, multi-source orders table -- proof the two ingestion
    paths (SFTP + batch ETL) really did land in one queryable place."""
    con = get_duckdb()
    rows = con.execute(
        "SELECT order_id, customer_name, product, quantity, total_price, country, source_system "
        "FROM mart_unified_orders ORDER BY source_system, order_id"
    ).fetchall()
    con.close()
    columns = ["order_id", "customer_name", "product", "quantity", "total_price", "country", "source_system"]
    return jsonify([dict(zip(columns, r)) for r in rows])


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
