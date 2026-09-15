"""
Week 4 — Loading data into Google BigQuery (a managed data warehouse).

Requires: pip install google-cloud-bigquery, and GCP credentials.
Not runnable in this sandbox (no GCP project/credentials available), so
this is reference code following the same load pattern already tested in
../../07_cloud/aws_s3_upload.py -- swap the destination client and the
shape of an ELT-style load into a warehouse stays the same.
"""
import os
from google.cloud import bigquery

HERE = os.path.dirname(os.path.abspath(__file__))


def load_dataframe_to_bigquery(df, dataset_id: str, table_id: str):
    client = bigquery.Client()
    table_ref = f"{client.project}.{dataset_id}.{table_id}"

    job_config = bigquery.LoadJobConfig(
        write_disposition="WRITE_TRUNCATE",  # this run's ELT load replaces the table
        autodetect=True,  # BigQuery infers the schema from the DataFrame --
    )                      # the "load raw, transform later" EL/ELT pattern

    job = client.load_table_from_dataframe(df, table_ref, job_config=job_config)
    job.result()  # blocks until the load job finishes
    print(f"[bigquery] loaded {len(df)} rows into {table_ref}")


def run_elt_query(sql: str):
    """The 'T' in ELT: a transformation query that runs using BigQuery's own
    compute, against data already loaded into the warehouse."""
    client = bigquery.Client()
    return client.query(sql).to_dataframe()


if __name__ == "__main__":
    import pandas as pd
    df = pd.read_csv(os.path.join(HERE, "..", "..", "02_etl_pipeline", "sample_data", "orders_raw.csv"))
    load_dataframe_to_bigquery(df, dataset_id="staging", table_id="orders_raw")
    result = run_elt_query("""
        SELECT country, SUM(CAST(quantity AS INT64) * CAST(unit_price AS FLOAT64)) AS revenue
        FROM `staging.orders_raw`
        GROUP BY country
        ORDER BY revenue DESC
    """)
    print(result)
