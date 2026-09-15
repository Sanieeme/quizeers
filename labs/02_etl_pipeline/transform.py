"""
Transform step: clean, validate, and reshape the raw orders.

This is where most of the "engineering" in an ETL pipeline lives:
- trimming whitespace and normalizing types
- dropping or flagging bad/incomplete records instead of silently corrupting them
- deriving new columns needed downstream (e.g. total_price)
"""
import pandas as pd


def transform_orders(raw: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Clean the raw orders DataFrame.

    Returns (clean_df, rejected_df) so bad records are quarantined rather
    than dropped silently — a real pipeline should always be able to show
    what it refused to load and why.
    """
    df = raw.copy()

    # Normalize whitespace on string columns
    for col in ["customer_name", "email", "product", "country"]:
        df[col] = df[col].astype(str).str.strip()
        df[col] = df[col].replace({"nan": None, "": None})

    # Coerce numeric/date columns; invalid values become NaT/NaN instead of
    # raising, so we can quarantine those rows instead of crashing the job
    df["quantity"] = pd.to_numeric(df["quantity"], errors="coerce")
    df["unit_price"] = pd.to_numeric(df["unit_price"], errors="coerce")
    df["order_date"] = pd.to_datetime(df["order_date"], errors="coerce")

    # A record is valid only if every required field parsed correctly
    required = ["customer_name", "email", "product", "quantity", "unit_price", "order_date"]
    is_valid = df[required].notna().all(axis=1)

    clean = df[is_valid].copy()
    rejected = df[~is_valid].copy()

    # Derive a new column — this is the "value-add" part of transform
    clean["total_price"] = (clean["quantity"] * clean["unit_price"]).round(2)
    clean["order_date"] = clean["order_date"].dt.date.astype(str)

    print(f"[transform] {len(clean)} valid rows, {len(rejected)} rejected rows")
    return clean.reset_index(drop=True), rejected.reset_index(drop=True)


if __name__ == "__main__":
    from extract import extract_orders

    raw = extract_orders("sample_data/orders_raw.csv")
    clean, rejected = transform_orders(raw)
    print("\nClean:\n", clean)
    print("\nRejected:\n", rejected)
