"""
A runnable, broker-free simulation of the producer/consumer/topic/partition
concepts from producer.py and consumer.py -- useful for demonstrating and
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
    """Returns a stateful handler that keeps a running average score per
    quiz category -- demonstrating the kind of stateful aggregation a real
    stream processor (Kafka Streams, Spark Structured Streaming, Flink)
    would do."""
    sums = {}
    counts = {}
    averages = {}

    def handle(partition, event):
        category = event["category"]
        sums[category] = sums.get(category, 0) + event["score_percent"]
        counts[category] = counts.get(category, 0) + 1
        averages[category] = round(sums[category] / counts[category], 2)
        print(f"[consumer] partition={partition} processed attempt {event['attempt_id']} "
              f"-> running average score for {category}: {averages[category]}")

    return handle, averages


def main():
    attempts_topic = SimulatedTopic("quiz_attempts", num_partitions=3)

    sample_events = [
        {"attempt_id": 6001, "quiz_title": "Apache Kafka", "category": "Processing", "score_percent": 70.0},
        {"attempt_id": 6002, "quiz_title": "Apache Airflow", "category": "Orchestration", "score_percent": 100.0},
        {"attempt_id": 6003, "quiz_title": "Apache Spark", "category": "Processing", "score_percent": 81.82},
        {"attempt_id": 6004, "quiz_title": "Relational Databases and SQL", "category": "Databases", "score_percent": 92.31},
        {"attempt_id": 6005, "quiz_title": "Data Ingestion Methods", "category": "Processing", "score_percent": 60.0},
    ]

    # Produce: each event is keyed by attempt_id, same pattern as producer.py
    for event in sample_events:
        event_with_ts = {**event, "event_time": datetime.now(timezone.utc).isoformat()}
        attempts_topic.produce(key=str(event["attempt_id"]), value=event_with_ts)

    print()
    # Consume: process every partition and keep a running aggregate,
    # like a stream-processing job would
    handle, averages = running_totals_consumer()
    attempts_topic.consume_all(handle)

    print("\n[consumer] final running average scores by category:", averages)
    return averages


if __name__ == "__main__":
    main()
