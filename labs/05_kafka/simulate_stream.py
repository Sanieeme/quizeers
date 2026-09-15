"""
A runnable, broker-free simulation of the producer/consumer/topic/partition
concepts from producer.py and consumer.py — useful for demonstrating and
testing the *logic* of a streaming pipeline without standing up a real
Kafka cluster.

This is NOT a replacement for Kafka: there's no durability, no replication,
no cross-machine networking. It exists so this lab has something you can
actually run end-to-end to prove the streaming design works, before pointing
producer.py/consumer.py at a real broker.
"""
import queue
import threading
import time
from datetime import datetime, timezone


class SimulatedTopic:
    """Stands in for a Kafka topic with N partitions, each a FIFO queue."""

    def __init__(self, name: str, num_partitions: int = 3):
        self.name = name
        self.partitions = [queue.Queue() for _ in range(num_partitions)]

    def _partition_for_key(self, key: str) -> int:
        # Kafka partitions by hash(key) % num_partitions so all events with
        # the same key land in the same partition, preserving per-key order
        return hash(key) % len(self.partitions)

    def produce(self, key: str, value: dict):
        p = self._partition_for_key(key)
        self.partitions[p].put(value)
        print(f"[producer] -> topic={self.name} partition={p} key={key} value={value}")

    def consume_all(self, handle_fn, timeout=1.0):
        """A simple single-threaded consumer that drains every partition."""
        for p_idx, p in enumerate(self.partitions):
            while True:
                try:
                    value = p.get(timeout=timeout)
                except queue.Empty:
                    break
                handle_fn(p_idx, value)


def running_totals_consumer():
    """Returns a stateful handler that keeps a running revenue total per
    country — demonstrating the kind of stateful aggregation a real stream
    processor (Kafka Streams, Spark Structured Streaming, Flink) would do."""
    totals = {}

    def handle(partition, event):
        country = event["country"]
        revenue = event["quantity"] * event["unit_price"]
        totals[country] = totals.get(country, 0) + revenue
        print(f"[consumer] partition={partition} processed order {event['order_id']} "
              f"-> running total for {country}: {totals[country]:.2f}")

    return handle, totals


def main():
    orders_topic = SimulatedTopic("orders", num_partitions=3)

    sample_events = [
        {"order_id": 3001, "product": "Widget A", "quantity": 3, "unit_price": 9.99, "country": "South Africa"},
        {"order_id": 3002, "product": "Widget B", "quantity": 1, "unit_price": 24.50, "country": "USA"},
        {"order_id": 3003, "product": "Widget A", "quantity": 2, "unit_price": 9.99, "country": "South Africa"},
        {"order_id": 3004, "product": "Widget C", "quantity": 5, "unit_price": 4.25, "country": "Kenya"},
        {"order_id": 3005, "product": "Widget B", "quantity": 2, "unit_price": 24.50, "country": "USA"},
    ]

    # Produce: each event is keyed by order_id, same pattern as producer.py
    for event in sample_events:
        event_with_ts = {**event, "event_time": datetime.now(timezone.utc).isoformat()}
        orders_topic.produce(key=str(event["order_id"]), value=event_with_ts)

    print()
    # Consume: process every partition and keep a running aggregate,
    # like a stream-processing job would
    handle, totals = running_totals_consumer()
    orders_topic.consume_all(handle)

    print("\n[consumer] final running totals by country:", totals)
    return totals


if __name__ == "__main__":
    main()
