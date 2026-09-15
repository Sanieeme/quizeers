"""
Extract step: pull raw order data from a source file.

In a real pipeline this would hit an API, a database, or object storage
(S3/GCS/Blob). Here it reads a CSV to keep the lab self-contained, but the
function signature is the same shape you'd use for any source.
"""
import pandas as pd


def extract_orders(path: str) -> pd.DataFrame:
    """Read raw order records from a CSV file into a DataFrame."""
    df = pd.read_csv(path, dtype=str)  # read everything as string first;
    # deferring type coercion to the transform step is a common ETL pattern
    # so extraction never fails just because a downstream type doesn't parse.
    print(f"[extract] read {len(df)} raw rows from {path}")
    return df


if __name__ == "__main__":
    df = extract_orders("sample_data/orders_raw.csv")
    print(df.head())
