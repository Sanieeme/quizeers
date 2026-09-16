"""
Load step: write the cleaned data to a target store.

This targets a local SQLite database to keep the lab runnable anywhere, but
swapping the connection string for Postgres, Redshift, BigQuery, or Snowflake
is the only change needed to point this at a real warehouse.
"""
import sqlite3
import pandas as pd


def load_quiz_attempts(clean: pd.DataFrame, rejected: pd.DataFrame, db_path: str) -> None:
    con = sqlite3.connect(db_path)
    try:
        clean.to_sql("quiz_attempts", con, if_exists="replace", index=False)
        rejected.to_sql("quiz_attempts_rejected", con, if_exists="replace", index=False)
        con.commit()
        print(f"[load] wrote {len(clean)} rows to 'quiz_attempts' and "
              f"{len(rejected)} to 'quiz_attempts_rejected' in {db_path}")
    finally:
        con.close()


if __name__ == "__main__":
    from extract import extract_quiz_attempts
    from transform import transform_quiz_attempts

    raw = extract_quiz_attempts("sample_data/quiz_attempts_raw.csv")
    clean, rejected = transform_quiz_attempts(raw)
    load_quiz_attempts(clean, rejected, "output/warehouse.db")
