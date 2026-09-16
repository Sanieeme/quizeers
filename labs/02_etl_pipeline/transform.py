"""
Transform step: clean, validate, and reshape the raw quiz attempts.

This is where most of the "engineering" in an ETL pipeline lives:
- trimming whitespace and normalizing types
- dropping or flagging bad/incomplete records instead of silently corrupting them
- deriving new columns needed downstream (e.g. score_percent)
"""
import pandas as pd


def transform_quiz_attempts(raw: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Clean the raw quiz-attempts DataFrame.

    Returns (clean_df, rejected_df) so bad records are quarantined rather
    than dropped silently -- a real pipeline should always be able to show
    what it refused to load and why.
    """
    df = raw.copy()

    # Normalize whitespace on string columns
    for col in ["user_name", "email", "quiz_title", "category"]:
        df[col] = df[col].astype(str).str.strip()
        df[col] = df[col].replace({"nan": None, "": None})

    # Coerce numeric/date columns; invalid values become NaT/NaN instead of
    # raising, so we can quarantine those rows instead of crashing the job
    df["questions_total"] = pd.to_numeric(df["questions_total"], errors="coerce")
    df["questions_correct"] = pd.to_numeric(df["questions_correct"], errors="coerce")
    df["attempted_at"] = pd.to_datetime(df["attempted_at"], errors="coerce")

    # A record is valid only if every required field parsed correctly
    # (category is informational only, like "country" was in the orders
    # version of this lab -- it's not required for a row to be valid)
    required = ["user_name", "email", "quiz_title", "questions_total", "questions_correct", "attempted_at"]
    is_valid = df[required].notna().all(axis=1)

    clean = df[is_valid].copy()
    rejected = df[~is_valid].copy()

    # Derive a new column -- this is the "value-add" part of transform
    clean["score_percent"] = (clean["questions_correct"] / clean["questions_total"] * 100).round(2)
    clean["attempted_at"] = clean["attempted_at"].dt.date.astype(str)

    print(f"[transform] {len(clean)} valid rows, {len(rejected)} rejected rows")
    return clean.reset_index(drop=True), rejected.reset_index(drop=True)


if __name__ == "__main__":
    from extract import extract_quiz_attempts

    raw = extract_quiz_attempts("sample_data/quiz_attempts_raw.csv")
    clean, rejected = transform_quiz_attempts(raw)
    print("\nClean:\n", clean)
    print("\nRejected:\n", rejected)
