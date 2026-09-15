"""
Week 4 — ETL vs. EL vs. ELT, implemented as three real, runnable variants
of the same job instead of just defined.

- ETL: transform in the pipeline's own process, before loading (what
  ../../02_etl_pipeline/ does).
- EL:  load the raw data as-is, transform later/elsewhere.
- ELT: load raw, then transform INSIDE the destination using its own
  query engine (here, SQL run inside SQLite) -- this is the pattern behind
  BigQuery/Snowflake-centric pipelines, where the warehouse's own compute
  does the transformation instead of a separate processing job.
"""
import os
import sqlite3
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE_CSV = os.path.join(HERE, "..", "..", "02_etl_pipeline", "sample_data", "orders_raw.csv")


def run_etl():
    """Transform happens in Python, before loading."""
    df = pd.read_csv(SOURCE_CSV, dtype=str)
    df["quantity"] = pd.to_numeric(df["quantity"], errors="coerce")
    df["unit_price"] = pd.to_numeric(df["unit_price"], errors="coerce")
    valid = df.dropna(subset=["quantity", "unit_price", "customer_name"])
    valid = valid.copy()
    valid["total_price"] = (valid["quantity"] * valid["unit_price"]).round(2)

    con = sqlite3.connect(os.path.join(HERE, "etl_output.db"))
    valid.to_sql("orders", con, if_exists="replace", index=False)
    con.close()
    print(f"[ETL] transformed in Python, loaded {len(valid)} already-clean rows")


def run_el():
    """Load raw data completely as-is -- no transformation at all yet.
    Whoever queries this table later must handle the mess themselves."""
    df = pd.read_csv(SOURCE_CSV, dtype=str)  # untouched -- includes bad rows, string types
    con = sqlite3.connect(os.path.join(HERE, "el_output.db"))
    df.to_sql("orders_raw", con, if_exists="replace", index=False)
    con.close()
    print(f"[EL] loaded {len(df)} raw rows completely untouched -- includes bad data")


def run_elt():
    """Load raw data (same as EL), then transform IN the destination using
    its own SQL engine -- no separate Python transform step."""
    run_el()  # the "EL" part is identical
    con = sqlite3.connect(os.path.join(HERE, "el_output.db"))
    # The "T" happens here, as a SQL statement executed by the destination
    # engine itself -- this is exactly what a dbt model or a BigQuery
    # scheduled query does against data already sitting in the warehouse.
    con.execute("DROP TABLE IF EXISTS orders_transformed")
    con.execute("""
        CREATE TABLE orders_transformed AS
        SELECT
            order_id,
            TRIM(customer_name) AS customer_name,
            TRIM(email) AS email,
            TRIM(product) AS product,
            CAST(quantity AS INTEGER) AS quantity,
            CAST(unit_price AS REAL) AS unit_price,
            ROUND(CAST(quantity AS REAL) * CAST(unit_price AS REAL), 2) AS total_price,
            order_date,
            TRIM(country) AS country
        FROM orders_raw
        WHERE customer_name IS NOT NULL AND TRIM(customer_name) != ''
          AND quantity IS NOT NULL AND TRIM(quantity) != ''
          AND unit_price IS NOT NULL AND TRIM(unit_price) != ''
    """)
    n = con.execute("SELECT COUNT(*) FROM orders_transformed").fetchone()[0]
    con.commit()
    con.close()
    print(f"[ELT] transformed {n} rows using SQL running INSIDE the destination database")


if __name__ == "__main__":
    for f in ["etl_output.db", "el_output.db"]:
        p = os.path.join(HERE, f)
        if os.path.exists(p):
            os.remove(p)

    run_etl()
    run_elt()

    print("\nWhen to prefer which:")
    print("- ETL: transform logic is complex/reusable, or the destination has weak compute (e.g. an app DB)")
    print("- ELT: destination is a powerful warehouse (BigQuery/Snowflake) -- let it do the heavy lifting")
    print("- EL alone: destination is a lake meant to hold raw data for multiple future uses")
