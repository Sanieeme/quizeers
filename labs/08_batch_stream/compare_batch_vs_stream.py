"""
Runs the same quiz-attempt data through a batch job and a stream-processing
job side by side, so the trade-offs are visible directly rather than just
described.

Batch: the whole dataset is read at once (02_etl_pipeline), and results are
only available after the full job finishes -- but it's simple and efficient
for large historical processing.

Stream: each event is processed the moment it "arrives" (05_kafka's
simulation), so a running average score is available immediately after
every single attempt -- at the cost of extra bookkeeping (state, ordering,
partitions).
"""
import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "02_etl_pipeline"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "05_kafka"))


def run_batch_job():
    from extract import extract_quiz_attempts
    from transform import transform_quiz_attempts

    print("=== BATCH job ===")
    start = time.time()
    raw = extract_quiz_attempts(os.path.join(os.path.dirname(__file__), "..", "02_etl_pipeline", "sample_data", "quiz_attempts_raw.csv"))
    clean, _ = transform_quiz_attempts(raw)
    averages = clean.groupby("category")["score_percent"].mean().round(2).to_dict()
    elapsed = time.time() - start
    print(f"[batch] result only available after the FULL job completes ({elapsed:.3f}s for {len(clean)} rows)")
    print(f"[batch] final average scores by category: {averages}")
    return averages


def run_stream_job():
    from simulate_stream import SimulatedTopic, running_totals_consumer
    from datetime import datetime, timezone

    print("\n=== STREAM job ===")
    topic = SimulatedTopic("quiz_attempts_stream", num_partitions=1)  # single partition -> strict order for this demo
    handle, averages = running_totals_consumer()

    events = [
        {"attempt_id": 8001, "quiz_title": "Apache Kafka", "category": "Processing", "score_percent": 70.0},
        {"attempt_id": 8002, "quiz_title": "Apache Airflow", "category": "Orchestration", "score_percent": 100.0},
        {"attempt_id": 8003, "quiz_title": "Apache Spark", "category": "Processing", "score_percent": 81.82},
    ]

    for e in events:
        topic.produce(key=str(e["attempt_id"]), value={**e, "event_time": datetime.now(timezone.utc).isoformat()})
        # process immediately, one at a time -- this is the key contrast with batch
        topic.consume_all(handle)
        print(f"[stream] result available immediately after attempt {e['attempt_id']}: {averages}")

    return averages


if __name__ == "__main__":
    batch_averages = run_batch_job()
    stream_averages = run_stream_job()
    print("\n=== Takeaway ===")
    print("Batch gives you one complete, consistent answer after processing everything.")
    print("Stream gives you an up-to-date (but continuously changing) answer after every event.")
