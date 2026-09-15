-- A small star schema: one fact table (fact_sales) surrounded by
-- dimension tables. This is the pattern behind most data warehouses,
-- whether it's implemented in Postgres, Redshift, BigQuery, or Snowflake.

CREATE TABLE IF NOT EXISTS dim_customer (
    customer_id   INTEGER PRIMARY KEY,
    customer_name TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    country       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dim_product (
    product_id   INTEGER PRIMARY KEY,
    product_name TEXT NOT NULL UNIQUE,
    unit_price   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS dim_date (
    date_id  INTEGER PRIMARY KEY,   -- YYYYMMDD
    full_date TEXT NOT NULL,
    year     INTEGER NOT NULL,
    month    INTEGER NOT NULL,
    day      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS fact_sales (
    order_id    INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES dim_customer(customer_id),
    product_id  INTEGER NOT NULL REFERENCES dim_product(product_id),
    date_id     INTEGER NOT NULL REFERENCES dim_date(date_id),
    quantity    INTEGER NOT NULL,
    total_price REAL NOT NULL
);

-- Example analytical query enabled by this shape: revenue by country and month
-- SELECT c.country, d.year, d.month, SUM(f.total_price) AS revenue
-- FROM fact_sales f
-- JOIN dim_customer c ON c.customer_id = f.customer_id
-- JOIN dim_date d ON d.date_id = f.date_id
-- GROUP BY c.country, d.year, d.month
-- ORDER BY revenue DESC;
