"""
Takes the flat 'orders' table produced by the ETL pipeline (02_etl_pipeline)
and loads it into a proper star schema: dim_customer, dim_product, dim_date,
fact_sales. Then runs an example OLAP-style aggregation query to show why
the shape is useful.
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
    orders = pd.read_sql("SELECT * FROM orders", src)
    src.close()

    tgt = sqlite3.connect(TARGET_DB)
    with open(SCHEMA_FILE) as f:
        tgt.executescript(f.read())

    # dim_customer
    customers = orders[["customer_name", "email", "country"]].drop_duplicates().reset_index(drop=True)
    customers.insert(0, "customer_id", customers.index + 1)
    customers.to_sql("dim_customer", tgt, if_exists="replace", index=False)

    # dim_product
    products = orders[["product", "unit_price"]].drop_duplicates().reset_index(drop=True)
    products.insert(0, "product_id", products.index + 1)
    products.columns = ["product_id", "product_name", "unit_price"]
    products.to_sql("dim_product", tgt, if_exists="replace", index=False)

    # dim_date
    dates = orders[["order_date"]].drop_duplicates().reset_index(drop=True)
    dates["date_id"] = dates["order_date"].str.replace("-", "").astype(int)
    dates["year"] = dates["order_date"].str.slice(0, 4).astype(int)
    dates["month"] = dates["order_date"].str.slice(5, 7).astype(int)
    dates["day"] = dates["order_date"].str.slice(8, 10).astype(int)
    dates = dates.rename(columns={"order_date": "full_date"})[["date_id", "full_date", "year", "month", "day"]]
    dates.to_sql("dim_date", tgt, if_exists="replace", index=False)

    # fact_sales: join keys back onto the flat orders table
    merged = orders.merge(customers, on=["customer_name", "email", "country"])
    merged = merged.merge(products, left_on="product", right_on="product_name")
    merged["date_id"] = merged["order_date"].str.replace("-", "").astype(int)
    fact = merged[["order_id", "customer_id", "product_id", "date_id", "quantity", "total_price"]]
    fact.to_sql("fact_sales", tgt, if_exists="replace", index=False)

    tgt.commit()
    print(f"[warehouse] loaded {len(customers)} customers, {len(products)} products, "
          f"{len(dates)} dates, {len(fact)} fact rows into {TARGET_DB}")

    print("\n[warehouse] revenue by country:")
    q = """
        SELECT c.country, SUM(f.total_price) AS revenue
        FROM fact_sales f
        JOIN dim_customer c ON c.customer_id = f.customer_id
        GROUP BY c.country
        ORDER BY revenue DESC
    """
    print(pd.read_sql(q, tgt))
    tgt.close()


if __name__ == "__main__":
    build()
