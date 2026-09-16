"""
Takes the flat 'quiz_attempts' table produced by the ETL pipeline
(02_etl_pipeline) and loads it into a proper star schema: dim_user,
dim_quiz, dim_date, fact_attempt. Then runs an example OLAP-style
aggregation query to show why the shape is useful.
"""
import os
import sqlite3
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE_DB = os.path.join(HERE, "..", "02_etl_pipeline", "output", "warehouse.db")
TARGET_DB = os.path.join(HERE, "warehouse_star.db")
SCHEMA_FILE = os.path.join(HERE, "warehouse_schema.sql")


def build():
    src = sqlite3.connect(SOURCE_DB)
    attempts = pd.read_sql("SELECT * FROM quiz_attempts", src)
    src.close()

    tgt = sqlite3.connect(TARGET_DB)
    with open(SCHEMA_FILE) as f:
        tgt.executescript(f.read())

    # dim_user
    users = attempts[["user_name", "email"]].drop_duplicates().reset_index(drop=True)
    users.insert(0, "user_id", users.index + 1)
    users.to_sql("dim_user", tgt, if_exists="replace", index=False)

    # dim_quiz
    quizzes = attempts[["quiz_title", "category"]].drop_duplicates().reset_index(drop=True)
    quizzes.insert(0, "quiz_id", quizzes.index + 1)
    quizzes.to_sql("dim_quiz", tgt, if_exists="replace", index=False)

    # dim_date
    dates = attempts[["attempted_at"]].drop_duplicates().reset_index(drop=True)
    dates["date_id"] = dates["attempted_at"].str.replace("-", "").astype(int)
    dates["year"] = dates["attempted_at"].str.slice(0, 4).astype(int)
    dates["month"] = dates["attempted_at"].str.slice(5, 7).astype(int)
    dates["day"] = dates["attempted_at"].str.slice(8, 10).astype(int)
    dates = dates.rename(columns={"attempted_at": "full_date"})[["date_id", "full_date", "year", "month", "day"]]
    dates.to_sql("dim_date", tgt, if_exists="replace", index=False)

    # fact_attempt: join keys back onto the flat attempts table
    merged = attempts.merge(users, on=["user_name", "email"])
    merged = merged.merge(quizzes, on=["quiz_title", "category"])
    merged["date_id"] = merged["attempted_at"].str.replace("-", "").astype(int)
    fact = merged[["attempt_id", "user_id", "quiz_id", "date_id",
                    "questions_total", "questions_correct", "score_percent"]]
    fact.to_sql("fact_attempt", tgt, if_exists="replace", index=False)

    tgt.commit()
    print(f"[warehouse] loaded {len(users)} users, {len(quizzes)} quizzes, "
          f"{len(dates)} dates, {len(fact)} fact rows into {TARGET_DB}")

    print("\n[warehouse] average score by quiz category:")
    q = """
        SELECT q.category, ROUND(AVG(f.score_percent), 2) AS avg_score
        FROM fact_attempt f
        JOIN dim_quiz q ON q.quiz_id = f.quiz_id
        GROUP BY q.category
        ORDER BY avg_score DESC
    """
    print(pd.read_sql(q, tgt))
    tgt.close()


if __name__ == "__main__":
    build()
