"""
Load step: write the transformed aggregates into a separate analytics
warehouse database (analytics_warehouse.db).

Keeping this in a database file separate from quizeers.db is deliberate --
it's the same operational-vs-analytical split real data platforms use, so
the dashboard queries a warehouse built for reporting instead of hitting
the live app's transactional tables directly.
"""
import sqlite3
import pandas as pd


def load(transformed: dict, warehouse_db_path: str) -> None:
    con = sqlite3.connect(warehouse_db_path)
    try:
        for table_name, df in transformed.items():
            df.to_sql(table_name, con, if_exists="replace", index=False)
            print(f"[load] wrote {len(df)} rows to '{table_name}' in {warehouse_db_path}")
        con.commit()
    finally:
        con.close()


def read_table(warehouse_db_path: str, table_name: str) -> pd.DataFrame:
    con = sqlite3.connect(warehouse_db_path)
    try:
        # returns an empty DataFrame if the table doesn't exist yet, rather
        # than raising -- so the dashboard can render before the ETL has
        # ever been run
        cursor = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
        )
        if cursor.fetchone() is None:
            return pd.DataFrame()
        return pd.read_sql(f"SELECT * FROM {table_name}", con)
    finally:
        con.close()
