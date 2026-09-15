"""
Capstone — the "EL" half of an ELT flow: load raw data from each ingested
source into DuckDB (standing in for a warehouse) completely untransformed.
dbt then owns all transformation logic as SQL models (see models/), which
is exactly the ELT pattern from Week 4's etl_vs_el_vs_elt.py, applied here
with a real transformation tool instead of a single hand-written SQL string.
"""
import os
import duckdb
import pandas as pd
import psycopg2

HERE = os.path.dirname(os.path.abspath(__file__))
DUCKDB_PATH = os.path.join(HERE, "capstone.duckdb")
SFTP_CSV = os.path.join(HERE, "..", "ingestion", "downloaded", "daily_orders_extract.csv")
PG_CONN_STR = "dbname=quizeers_lab user=labuser password=labpass host=localhost"


def load_sftp_orders(con):
    df = pd.read_csv(SFTP_CSV)
    con.execute("CREATE OR REPLACE TABLE raw_sftp_orders AS SELECT * FROM df")
    print(f"[load] raw_sftp_orders: {len(df)} rows")


def load_inventory_from_postgres(con):
    pg = psycopg2.connect(PG_CONN_STR)
    df = pd.read_sql("SELECT sku, product_name, quantity_on_hand, updated_at FROM inventory", pg)
    pg.close()
    con.execute("CREATE OR REPLACE TABLE raw_inventory AS SELECT * FROM df")
    print(f"[load] raw_inventory: {len(df)} rows (current state after CDC-applied changes)")


def load_batch_orders_from_etl(con):
    """Also brings in the original ETL pipeline's warehouse.db orders table,
    so the capstone mart can report on orders from BOTH the SFTP source and
    the original batch ETL source -- a genuine multi-source join."""
    import sqlite3
    etl_db = os.path.join(HERE, "..", "..", "..", "02_etl_pipeline", "output", "warehouse.db")
    if not os.path.exists(etl_db):
        print("[load] no ETL warehouse.db found yet -- run 02_etl_pipeline/pipeline.py first; skipping")
        return
    sqlite_con = sqlite3.connect(etl_db)
    df = pd.read_sql("SELECT * FROM orders", sqlite_con)
    sqlite_con.close()
    con.execute("CREATE OR REPLACE TABLE raw_batch_orders AS SELECT * FROM df")
    print(f"[load] raw_batch_orders: {len(df)} rows")


if __name__ == "__main__":
    con = duckdb.connect(DUCKDB_PATH)
    load_sftp_orders(con)
    load_inventory_from_postgres(con)
    load_batch_orders_from_etl(con)
    con.close()
