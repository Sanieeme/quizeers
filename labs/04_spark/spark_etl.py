"""
A PySpark job that mirrors the same ETL logic as 02_etl_pipeline, but
expressed with Spark's DataFrame API so it can scale to a cluster.

Run with:  python3 spark_etl.py
(Runs in local mode — spark.master="local[*]" — using all cores on this
machine. Point it at a real cluster by changing the master URL.)
"""
import os
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType, IntegerType

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT_CSV = os.path.join(HERE, "..", "02_etl_pipeline", "sample_data", "orders_raw.csv")
OUTPUT_PARQUET = os.path.join(HERE, "output_parquet")


def main():
    spark = (
        SparkSession.builder
        .appName("orders-etl")
        .master("local[*]")
        .config("spark.sql.ansi.enabled", "false")  # let bad casts become NULL instead of raising,
        .getOrCreate()                               # so we can quarantine bad rows like the pandas version does
    )
    spark.sparkContext.setLogLevel("ERROR")

    # Extract
    raw = spark.read.option("header", True).csv(INPUT_CSV)
    print(f"[spark] read {raw.count()} raw rows")

    # Transform: trim strings, coerce types, derive total_price, drop bad rows
    df = raw
    for col in ["customer_name", "email", "product", "country"]:
        df = df.withColumn(col, F.trim(F.col(col)))

    df = (
        df.withColumn("quantity", F.col("quantity").cast(IntegerType()))
          .withColumn("unit_price", F.col("unit_price").cast(DoubleType()))
          .withColumn("order_date", F.to_date("order_date", "yyyy-MM-dd"))
    )

    string_required = ["customer_name", "email", "product"]
    typed_required = ["quantity", "unit_price", "order_date"]  # already cast to numeric/date types above

    valid_condition = None
    for col in string_required:
        cond = (F.col(col).isNotNull()) & (F.col(col) != "")
        valid_condition = cond if valid_condition is None else (valid_condition & cond)
    for col in typed_required:
        cond = F.col(col).isNotNull()  # comparing a typed column to "" would always be NULL, so just check null-ness
        valid_condition = valid_condition & cond

    clean = df.filter(valid_condition).withColumn(
        "total_price", F.round(F.col("quantity") * F.col("unit_price"), 2)
    )
    rejected = df.filter(~valid_condition)

    print(f"[spark] {clean.count()} valid rows, {rejected.count()} rejected rows")

    # Aggregation example: total revenue per country, computed distributed-ly
    print("[spark] revenue by country:")
    clean.groupBy("country").agg(F.sum("total_price").alias("revenue")) \
         .orderBy(F.desc("revenue")).show()

    # Load: write as partitioned Parquet, the columnar format covered in
    # 03/data_storage material — this is what a Spark job would hand off to
    # a warehouse loader or downstream consumer.
    clean.write.mode("overwrite").partitionBy("country").parquet(OUTPUT_PARQUET)
    print(f"[spark] wrote partitioned Parquet output to {OUTPUT_PARQUET}")

    spark.stop()


if __name__ == "__main__":
    main()
