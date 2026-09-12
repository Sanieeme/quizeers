"""
Extract step: pull raw operational data out of quizeers.db.

This is a genuine ETL "extract" in the classic sense: the source is the
live transactional database backing the app (OLTP), and the goal is to
pull it out into plain DataFrames so it can be reshaped for analytics
without touching the operational tables the app relies on for serving
requests.
"""
import sqlite3
import pandas as pd


def extract_all(operational_db_path: str) -> dict:
    """Read the tables needed for analytics out of the operational database.

    Returns a dict of DataFrames: attempts, question_attempts, questions,
    quizzes, users.
    """
    con = sqlite3.connect(operational_db_path)
    try:
        data = {
            "attempts": pd.read_sql("SELECT * FROM result", con),
            "question_attempts": pd.read_sql("SELECT * FROM question_attempt", con),
            "questions": pd.read_sql("SELECT * FROM question", con),
            "quizzes": pd.read_sql(
                "SELECT id, title, category, difficulty FROM quiz WHERE is_deleted = 0", con
            ),
            "users": pd.read_sql("SELECT id, email FROM user", con),
        }
    finally:
        con.close()

    for name, df in data.items():
        print(f"[extract] {name}: {len(df)} rows")
    return data


if __name__ == "__main__":
    import os
    db_path = os.path.join(os.path.dirname(__file__), "..", "quizeers.db")
    extract_all(db_path)
