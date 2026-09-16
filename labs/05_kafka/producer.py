"""
Real Kafka producer using kafka-python.

Requires a running Kafka broker (e.g. `docker run -p 9092:9092 apache/kafka`,
or a managed broker on AWS MSK / Confluent Cloud / GCP). This sandbox has no
Kafka broker available, so this script can't be executed here -- see
simulate_stream.py for a runnable, broker-free demo of the same concepts
(producer/consumer decoupling, topics, partitions-as-queues).

Usage against a real broker:
    python3 producer.py --bootstrap-servers localhost:9092 --topic quiz_attempts
"""
import argparse
import json
import time
from datetime import datetime, timezone

from kafka import KafkaProducer


SAMPLE_ATTEMPTS = [
    {"attempt_id": 7001, "quiz_title": "Apache Kafka", "category": "Processing", "score_percent": 70.0},
    {"attempt_id": 7002, "quiz_title": "Apache Airflow", "category": "Orchestration", "score_percent": 100.0},
    {"attempt_id": 7003, "quiz_title": "Cloud Platforms for Data Engineering", "category": "Cloud", "score_percent": 66.67},
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument("--topic", default="quiz_attempts")
    args = parser.parse_args()

    producer = KafkaProducer(
        bootstrap_servers=args.bootstrap_servers,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    for attempt in SAMPLE_ATTEMPTS:
        event = {**attempt, "event_time": datetime.now(timezone.utc).isoformat()}
        # key by attempt_id so all events for the same attempt land on the
        # same partition and are processed in order by a single consumer
        producer.send(args.topic, key=str(attempt["attempt_id"]).encode(), value=event)
        print(f"[producer] sent {event}")
        time.sleep(0.5)

    producer.flush()
    producer.close()


if __name__ == "__main__":
    main()
