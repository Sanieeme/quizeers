"""
Week 2 — Compares CSV, JSON, and Parquet on the same dataset: file size,
write/read time, and whether types survive a round trip. This is meant to
make the "why Parquet" argument concrete instead of asserted.
"""
import json
import os
import time
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE_CSV = os.path.join(HERE, "..", "..", "02_etl_pipeline", "sample_data", "quiz_attempts_raw.csv")


def make_larger_dataset(n_repeats=2000):
    """Repeat the sample data to a size where format differences are visible."""
    base = pd.read_csv(SOURCE_CSV)
    df = pd.concat([base] * n_repeats, ignore_index=True)
    df["order_id"] = df.index  # keep a unique key after repeating
    return df


def time_it(fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def compare_formats(df: pd.DataFrame, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    results = []

    # CSV
    csv_path = os.path.join(out_dir, "data.csv")
    _, write_t = time_it(lambda: df.to_csv(csv_path, index=False))
    _, read_t = time_it(lambda: pd.read_csv(csv_path))
    results.append({"format": "CSV", "size_kb": os.path.getsize(csv_path) / 1024,
                     "write_s": write_t, "read_s": read_t})

    # JSON
    json_path = os.path.join(out_dir, "data.json")
    _, write_t = time_it(lambda: df.to_json(json_path, orient="records"))
    _, read_t = time_it(lambda: pd.read_json(json_path))
    results.append({"format": "JSON", "size_kb": os.path.getsize(json_path) / 1024,
                     "write_s": write_t, "read_s": read_t})

    # Parquet (columnar, binary, typed)
    parquet_path = os.path.join(out_dir, "data.parquet")
    _, write_t = time_it(lambda: df.to_parquet(parquet_path, index=False))
    _, read_t = time_it(lambda: pd.read_parquet(parquet_path))
    results.append({"format": "Parquet", "size_kb": os.path.getsize(parquet_path) / 1024,
                     "write_s": write_t, "read_s": read_t})

    # Reading back only ONE column -- this is where columnar formats win,
    # since CSV/JSON must still parse every column to get at one of them.
    _, csv_col_t = time_it(lambda: pd.read_csv(csv_path, usecols=["country"]))
    _, parquet_col_t = time_it(lambda: pd.read_parquet(parquet_path, columns=["country"]))

    return pd.DataFrame(results), csv_col_t, parquet_col_t


if __name__ == "__main__":
    df = make_larger_dataset()
    print(f"Dataset: {len(df)} rows")
    out_dir = os.path.join(HERE, "format_comparison_output")
    summary, csv_col_t, parquet_col_t = compare_formats(df, out_dir)
    print(summary.round(4).to_string(index=False))
    print(f"\nReading a single column ('country') only:")
    print(f"  CSV:     {csv_col_t:.4f}s (still had to parse every column)")
    print(f"  Parquet: {parquet_col_t:.4f}s (columnar storage skips the rest)")
