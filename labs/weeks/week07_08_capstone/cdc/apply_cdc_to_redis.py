"""
Capstone — CDC consumer: polls the `cdc_log` table for new changes since
the last checkpoint, and applies each one to Redis (the high-velocity
store used to serve real-time queries — see ../api/serve.py).

This is the same role a Kafka Connect sink connector would play in a real
Debezium setup (Postgres WAL -> Debezium -> Kafka topic -> sink connector
-> destination); here the "topic" is simply the cdc_log table being
polled directly, which keeps the whole chain runnable without a Kafka
broker while preserving the ordered, change-by-change apply semantics.
"""
import json
import os
import psycopg2
import redis

CONN_STR = "dbname=quizeers_lab user=labuser password=labpass host=localhost"
CHECKPOINT_FILE = os.path.join(os.path.dirname(__file__), "_checkpoint.txt")


def get_checkpoint() -> int:
    if os.path.exists(CHECKPOINT_FILE):
        return int(open(CHECKPOINT_FILE).read().strip())
    return 0


def set_checkpoint(log_id: int):
    with open(CHECKPOINT_FILE, "w") as f:
        f.write(str(log_id))


def apply_changes():
    pg = psycopg2.connect(CONN_STR)
    cur = pg.cursor()
    r = redis.Redis(host="localhost", port=6379, decode_responses=True)

    last_seen = get_checkpoint()
    cur.execute(
        "SELECT log_id, op, sku, after_data FROM cdc_log WHERE log_id > %s ORDER BY log_id",
        (last_seen,),
    )
    changes = cur.fetchall()

    applied = 0
    for log_id, op, sku, after_data in changes:
        redis_key = f"inventory:{sku}"
        if op in ("INSERT", "UPDATE"):
            r.set(redis_key, json.dumps(after_data))
            print(f"[cdc-apply] log_id={log_id} {op} {sku} -> Redis SET {redis_key}")
        elif op == "DELETE":
            r.delete(redis_key)
            print(f"[cdc-apply] log_id={log_id} {op} {sku} -> Redis DEL {redis_key}")
        applied += 1
        set_checkpoint(log_id)

    print(f"[cdc-apply] applied {applied} changes (checkpoint now at log_id={get_checkpoint()})")
    cur.close()
    pg.close()
    return applied


if __name__ == "__main__":
    apply_changes()
