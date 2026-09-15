"""
Runs the same order data through a batch job and a stream-processing job
side by side, so the trade-offs are visible directly rather than just
described.

Batch: the whole dataset is read at once (02_etl_pipeline), and results are
only available after the full job finishes — but it's simple and efficient
for large historical processing.

Stream: each event is processed the moment it "arrives" (05_kafka's
simulation), so a running total is available immediately after every single
order — at the cost of extra bookkeeping (state, ordering, partitions).
"""
import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "02_etl_pipeline"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "05_kafka"))


def run_batch_job():
    from extract import extract_orders
    from transform import transform_orders

    print("=== BATCH job ===")
    start = time.time()
    raw = extract_orders(os.path.join(os.path.dirname(__file__), "..", "02_etl_pipeline", "sample_data", "orders_raw.csv"))
    clean, _ = transform_orders(raw)
    totals = clean.groupby("country")["total_price"].sum().to_dict()
    elapsed = time.time() - start
    print(f"[batch] result only available after the FULL job completes ({elapsed:.3f}s for {len(clean)} rows)")
    print(f"[batch] final totals by country: {totals}")
    return totals


def run_stream_job():
    from simulate_stream import SimulatedTopic, running_totals_consumer
    from datetime import datetime, timezone

    print("\n=== STREAM job ===")
    topic = SimulatedTopic("orders_stream", num_partitions=1)  # single partition -> strict order for this demo
    handle, totals = running_totals_consumer()

    events = [
        {"order_id": 4001, "product": "Widget A", "quantity": 3, "unit_price": 9.99, "country": "South Africa"},
        {"order_id": 4002, "product": "Widget B", "quantity": 1, "unit_price": 24.50, "country": "USA"},
        {"order_id": 4003, "product": "Widget A", "quantity": 2, "unit_price": 9.99, "country": "South Africa"},
    ]

    for e in events:
        topic.produce(key=str(e["order_id"]), value={**e, "event_time": datetime.now(timezone.utc).isoformat()})
        # process immediately, one at a time -- this is the key contrast with batch
        topic.consume_all(handle)
        print(f"[stream] result available immediately after order {e['order_id']}: {totals}")

    return totals


if __name__ == "__main__":
    batch_totals = run_batch_job()
    stream_totals = run_stream_job()
    print("\n=== Takeaway ===")
    print("Batch gives you one complete, consistent answer after processing everything.")
    print("Stream gives you an up-to-date (but continuously changing) answer after every event.")
