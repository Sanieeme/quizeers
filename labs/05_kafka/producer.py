"""
Real Kafka producer using kafka-python.

Requires a running Kafka broker (e.g. `docker run -p 9092:9092 apache/kafka`,
or a managed broker on AWS MSK / Confluent Cloud / GCP). This sandbox has no
Kafka broker available, so this script can't be executed here — see
simulate_stream.py for a runnable, broker-free demo of the same concepts
(producer/consumer decoupling, topics, partitions-as-queues).

Usage against a real broker:
    python3 producer.py --bootstrap-servers localhost:9092 --topic orders
"""
import argparse
import json
import time
from datetime import datetime, timezone

from kafka import KafkaProducer


SAMPLE_ORDERS = [
    {"order_id": 2001, "product": "Widget A", "quantity": 2, "country": "South Africa"},
    {"order_id": 2002, "product": "Widget B", "quantity": 1, "country": "USA"},
    {"order_id": 2003, "product": "Widget C", "quantity": 5, "country": "Kenya"},
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument("--topic", default="orders")
    args = parser.parse_args()

    producer = KafkaProducer(
        bootstrap_servers=args.bootstrap_servers,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    for order in SAMPLE_ORDERS:
        event = {**order, "event_time": datetime.now(timezone.utc).isoformat()}
        # key by order_id so all events for the same order land on the same
        # partition and are processed in order by a single consumer
        producer.send(args.topic, key=str(order["order_id"]).encode(), value=event)
        print(f"[producer] sent {event}")
        time.sleep(0.5)

    producer.flush()
    producer.close()


if __name__ == "__main__":
    main()
