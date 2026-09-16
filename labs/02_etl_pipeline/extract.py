"""
Extract step: pull raw quiz-attempt data from a source file.

In a real pipeline this would hit an API, a database, or object storage
(S3/GCS/Blob) -- for Quizeers specifically, this is standing in for what
would otherwise be a read of the live quizeers.db `results`/`question_attempts`
tables (see analytics_etl/extract.py for that real version). Here it reads a
CSV to keep this lab self-contained, but the function signature is the same
shape you'd use for any source.
"""
import pandas as pd


def extract_quiz_attempts(path: str) -> pd.DataFrame:
    """Read raw quiz-attempt records from a CSV file into a DataFrame."""
    df = pd.read_csv(path, dtype=str)  # read everything as string first;
    # deferring type coercion to the transform step is a common ETL pattern
    # so extraction never fails just because a downstream type doesn't parse.
    print(f"[extract] read {len(df)} raw rows from {path}")
    return df


if __name__ == "__main__":
    df = extract_quiz_attempts("sample_data/quiz_attempts_raw.csv")
    print(df.head())
