"""
Week 6 — Data quality dimensions, implemented as real, runnable checks
against the orders dataset (not just defined). This is the "quality" pillar
of data governance made concrete: a set of automated assertions a pipeline
could run on every load before data is trusted downstream.
"""
import os
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE_CSV = os.path.join(HERE, "..", "..", "02_etl_pipeline", "sample_data", "orders_raw.csv")


def check_completeness(df: pd.DataFrame) -> dict:
    """Are required fields populated?"""
    required = ["customer_name", "email", "product", "quantity", "unit_price"]
    missing_counts = {col: df[col].isna().sum() + (df[col].astype(str).str.strip() == "").sum()
                       for col in required}
    total_cells = len(df) * len(required)
    total_missing = sum(missing_counts.values())
    score = 1 - (total_missing / total_cells) if total_cells else 1.0
    return {"dimension": "Completeness", "score": round(score, 3), "detail": missing_counts}


def check_uniqueness(df: pd.DataFrame) -> dict:
    """Are records that should be unique actually unique? (order_id here)"""
    dupes = df["order_id"].duplicated().sum()
    score = 1 - (dupes / len(df)) if len(df) else 1.0
    return {"dimension": "Uniqueness", "score": round(score, 3), "detail": {"duplicate_order_ids": int(dupes)}}


def check_validity(df: pd.DataFrame) -> dict:
    """Do values conform to expected types/formats? (quantity, unit_price numeric; date parses)"""
    quantity_valid = pd.to_numeric(df["quantity"], errors="coerce").notna()
    price_valid = pd.to_numeric(df["unit_price"], errors="coerce").notna()
    date_valid = pd.to_datetime(df["order_date"], errors="coerce").notna()
    total_checks = len(df) * 3
    total_valid = quantity_valid.sum() + price_valid.sum() + date_valid.sum()
    score = total_valid / total_checks if total_checks else 1.0
    return {
        "dimension": "Validity",
        "score": round(score, 3),
        "detail": {
            "invalid_quantity": int((~quantity_valid).sum()),
            "invalid_unit_price": int((~price_valid).sum()),
            "invalid_order_date": int((~date_valid).sum()),
        },
    }


def check_consistency(df: pd.DataFrame) -> dict:
    """Does the same real-world entity look the same everywhere it appears?
    Here: does the same email always map to the same customer_name?"""
    email_to_names = df.dropna(subset=["email"]).groupby("email")["customer_name"].nunique()
    inconsistent = (email_to_names > 1).sum()
    score = 1 - (inconsistent / len(email_to_names)) if len(email_to_names) else 1.0
    return {"dimension": "Consistency", "score": round(score, 3),
            "detail": {"emails_with_multiple_names": int(inconsistent)}}


def check_timeliness(df: pd.DataFrame, max_age_days: int = 365 * 5) -> dict:
    """Is the data recent enough to be useful? (flags dates far in the past/future)"""
    dates = pd.to_datetime(df["order_date"], errors="coerce")
    now = pd.Timestamp.now()
    stale = (dates < now - pd.Timedelta(days=max_age_days)) | (dates > now)
    valid_dates = dates.notna()
    score = 1 - (stale.sum() / valid_dates.sum()) if valid_dates.sum() else 1.0
    return {"dimension": "Timeliness", "score": round(score, 3), "detail": {"stale_or_future_dates": int(stale.sum())}}


def run_all_checks(df: pd.DataFrame) -> pd.DataFrame:
    checks = [check_completeness, check_uniqueness, check_validity, check_consistency, check_timeliness]
    results = [check(df) for check in checks]
    return pd.DataFrame([{"dimension": r["dimension"], "score": r["score"]} for r in results]), results


if __name__ == "__main__":
    df = pd.read_csv(SOURCE_CSV, dtype=str)
    summary, results = run_all_checks(df)
    print(summary.to_string(index=False))
    print()
    for r in results:
        print(f"{r['dimension']}: {r['detail']}")

    overall = summary["score"].mean()
    print(f"\nOverall data quality score: {overall:.1%}")
    if overall < 0.9:
        print("-> Below the 90% threshold this pipeline would gate on: "
              "route to a quarantine table and alert, rather than load into the warehouse.")
