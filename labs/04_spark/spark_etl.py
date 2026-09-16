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
INPUT_CSV = os.path.join(HERE, "..", "02_etl_pipeline", "sample_data", "quiz_attempts_raw.csv")
OUTPUT_PARQUET = os.path.join(HERE, "output_parquet")


def main():
    spark = (
        SparkSession.builder
        .appName("quiz-attempts-etl")
        .master("local[*]")
        .config("spark.sql.ansi.enabled", "false")  # let bad casts become NULL instead of raising,
        .getOrCreate()                               # so we can quarantine bad rows like the pandas version does
    )
    spark.sparkContext.setLogLevel("ERROR")

    # Extract
    raw = spark.read.option("header", True).csv(INPUT_CSV)
    print(f"[spark] read {raw.count()} raw rows")

    # Transform: trim strings, coerce types, derive score_percent, drop bad rows
    df = raw
    for col in ["user_name", "email", "quiz_title", "category"]:
        df = df.withColumn(col, F.trim(F.col(col)))

    df = (
        df.withColumn("questions_total", F.col("questions_total").cast(IntegerType()))
          .withColumn("questions_correct", F.col("questions_correct").cast(IntegerType()))
          .withColumn("attempted_at", F.to_date("attempted_at", "yyyy-MM-dd"))
    )

    string_required = ["user_name", "email", "quiz_title"]
    typed_required = ["questions_total", "questions_correct", "attempted_at"]  # already cast above

    valid_condition = None
    for col in string_required:
        cond = (F.col(col).isNotNull()) & (F.col(col) != "")
        valid_condition = cond if valid_condition is None else (valid_condition & cond)
    for col in typed_required:
        cond = F.col(col).isNotNull()  # comparing a typed column to "" would always be NULL, so just check null-ness
        valid_condition = valid_condition & cond

    clean = df.filter(valid_condition).withColumn(
        "score_percent", F.round(F.col("questions_correct") / F.col("questions_total") * 100, 2)
    )
    rejected = df.filter(~valid_condition)

    print(f"[spark] {clean.count()} valid rows, {rejected.count()} rejected rows")

    # Aggregation example: average score per quiz category, computed distributed-ly
    print("[spark] average score by category:")
    clean.groupBy("category").agg(F.round(F.avg("score_percent"), 2).alias("avg_score")) \
         .orderBy(F.desc("avg_score")).show()

    # Load: write as partitioned Parquet, the columnar format covered in
    # 03/data_storage material — this is what a Spark job would hand off to
    # a warehouse loader or downstream consumer.
    clean.write.mode("overwrite").partitionBy("category").parquet(OUTPUT_PARQUET)
    print(f"[spark] wrote partitioned Parquet output to {OUTPUT_PARQUET}")

    spark.stop()


if __name__ == "__main__":
    main()
