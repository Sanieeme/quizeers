"""
Real Kafka consumer using kafka-python. Pairs with producer.py.

Requires a running Kafka broker — see the note in producer.py.

Usage against a real broker:
    python3 consumer.py --bootstrap-servers localhost:9092 --topic orders --group order-processors
"""
import argparse
import json

from kafka import KafkaConsumer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument("--topic", default="orders")
    parser.add_argument("--group", default="order-processors")
    args = parser.parse_args()

    consumer = KafkaConsumer(
        args.topic,
        bootstrap_servers=args.bootstrap_servers,
        group_id=args.group,  # consumer group: lets multiple consumer processes
        auto_offset_reset="earliest",  # share the work of reading this topic's partitions
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    print(f"[consumer] listening on '{args.topic}' as group '{args.group}'...")
    for message in consumer:
        event = message.value
        print(f"[consumer] partition={message.partition} offset={message.offset} event={event}")
        # A real consumer would do something here: write to a warehouse,
        # trigger an alert, update a running aggregate, etc.


if __name__ == "__main__":
    main()
