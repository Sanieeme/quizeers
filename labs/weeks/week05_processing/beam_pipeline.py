"""
Week 5 — Apache Beam pipeline, run with the DirectRunner (local execution).

Beam's point is that the *same* pipeline code can run on different backends
(DirectRunner locally, DataflowRunner on GCP, FlinkRunner, SparkRunner) just
by changing the runner -- the pipeline logic itself doesn't change. This
mirrors the same ETL logic as ../../02_etl_pipeline/ and ../../04_spark/
spark_etl.py, expressed as a Beam pipeline of composable transforms (a
PCollection flowing through ParDo/Map/Filter steps) instead of Pandas
DataFrame calls or Spark's DataFrame API.
"""
import csv
import os
from datetime import datetime

import apache_beam as beam
from apache_beam.options.pipeline_options import PipelineOptions

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT_CSV = os.path.join(HERE, "..", "..", "02_etl_pipeline", "sample_data", "orders_raw.csv")
OUTPUT_PREFIX = os.path.join(HERE, "output", "orders_by_country")


def parse_csv_line(line: str, header: list) -> dict:
    reader = csv.reader([line])
    values = next(reader)
    return dict(zip(header, values))


class CleanAndValidate(beam.DoFn):
    """A ParDo transform: for each element, either yield a cleaned record
    or nothing at all (silently filtering bad rows would be wrong -- see
    the tagged-output version below for how a real pipeline would keep
    both outputs)."""

    def process(self, record: dict):
        try:
            name = (record.get("customer_name") or "").strip()
            email = (record.get("email") or "").strip()
            product = (record.get("product") or "").strip()
            country = (record.get("country") or "").strip()
            quantity = int(record["quantity"])
            unit_price = float(record["unit_price"])
            order_date = datetime.strptime(record["order_date"], "%Y-%m-%d")  # raises on "not-a-date"

            if not name or not email or not product:
                yield beam.pvalue.TaggedOutput("rejected", record)
                return

            yield {
                "order_id": record["order_id"],
                "customer_name": name,
                "product": product,
                "quantity": quantity,
                "unit_price": unit_price,
                "total_price": round(quantity * unit_price, 2),
                "country": country,
            }
        except (ValueError, KeyError):
            yield beam.pvalue.TaggedOutput("rejected", record)


def run():
    os.makedirs(os.path.join(HERE, "output"), exist_ok=True)
    options = PipelineOptions(
        runner="DirectRunner",
        direct_running_mode="in_memory",
        direct_num_workers=1,
    )

    with open(INPUT_CSV) as f:
        header = next(csv.reader(f))

    with beam.Pipeline(options=options) as pipeline:
        lines = (
            pipeline
            | "ReadCSV" >> beam.io.ReadFromText(INPUT_CSV, skip_header_lines=1)
        )

        parsed = lines | "ParseCSV" >> beam.Map(parse_csv_line, header=header)

        cleaned_and_rejected = parsed | "CleanAndValidate" >> beam.ParDo(
            CleanAndValidate()
        ).with_outputs("rejected", main="clean")

        clean = cleaned_and_rejected.clean
        rejected = cleaned_and_rejected.rejected

        # Aggregation: revenue by country -- a classic Beam Combine-per-key,
        # the same shape as Spark's groupBy().agg(sum(...))
        revenue_by_country = (
            clean
            | "KeyByCountry" >> beam.Map(lambda r: (r["country"], r["total_price"]))
            | "SumByCountry" >> beam.CombinePerKey(sum)
        )

        clean | "WriteClean" >> beam.io.WriteToText(
            os.path.join(HERE, "output", "clean"), file_name_suffix=".txt"
        )
        rejected | "WriteRejected" >> beam.io.WriteToText(
            os.path.join(HERE, "output", "rejected"), file_name_suffix=".txt"
        )
        revenue_by_country | "WriteRevenue" >> beam.io.WriteToText(
            os.path.join(HERE, "output", "revenue_by_country"), file_name_suffix=".txt"
        )
        revenue_by_country | "PrintRevenue" >> beam.Map(print)


if __name__ == "__main__":
    run()
