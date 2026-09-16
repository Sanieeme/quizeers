-- A small star schema: one fact table (fact_attempt) surrounded by
-- dimension tables. This is the pattern behind most data warehouses,
-- whether it's implemented in Postgres, Redshift, BigQuery, or Snowflake.
--
-- This is the same star-schema pattern the Quizeers app's own analytics
-- pipeline (analytics_etl/) uses on live quiz-attempt data -- this lab
-- builds it by hand, once, on a small sample so the mechanics are visible
-- step by step.

CREATE TABLE IF NOT EXISTS dim_user (
    user_id   INTEGER PRIMARY KEY,
    user_name TEXT NOT NULL,
    email     TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS dim_quiz (
    quiz_id    INTEGER PRIMARY KEY,
    quiz_title TEXT NOT NULL UNIQUE,
    category   TEXT
);

CREATE TABLE IF NOT EXISTS dim_date (
    date_id  INTEGER PRIMARY KEY,   -- YYYYMMDD
    full_date TEXT NOT NULL,
    year     INTEGER NOT NULL,
    month    INTEGER NOT NULL,
    day      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS fact_attempt (
    attempt_id        INTEGER PRIMARY KEY,
    user_id           INTEGER NOT NULL REFERENCES dim_user(user_id),
    quiz_id           INTEGER NOT NULL REFERENCES dim_quiz(quiz_id),
    date_id           INTEGER NOT NULL REFERENCES dim_date(date_id),
    questions_total   INTEGER NOT NULL,
    questions_correct INTEGER NOT NULL,
    score_percent     REAL NOT NULL
);

-- Example analytical query enabled by this shape: average score by quiz
-- category and month
-- SELECT q.category, d.year, d.month, ROUND(AVG(f.score_percent), 2) AS avg_score
-- FROM fact_attempt f
-- JOIN dim_quiz q ON q.quiz_id = f.quiz_id
-- JOIN dim_date d ON d.date_id = f.date_id
-- GROUP BY q.category, d.year, d.month
-- ORDER BY avg_score DESC;
