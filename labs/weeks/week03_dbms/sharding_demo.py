"""
Week 3 — Sharding: horizontally partitioning data across multiple physical
databases by a shard key, so no single node holds the entire dataset.

This uses 4 real, separate SQLite files as "shards" (in a real system these
would be separate DB servers) to make the routing logic concrete and testable.
"""
import hashlib
import os
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
NUM_SHARDS = 4


def shard_for_key(key: str, num_shards: int = NUM_SHARDS) -> int:
    """Consistent hashing (simplified): hash the shard key, mod by shard count.
    The same key always routes to the same shard."""
    digest = hashlib.md5(key.encode()).hexdigest()
    return int(digest, 16) % num_shards


def shard_path(shard_id: int) -> str:
    return os.path.join(HERE, f"shard_{shard_id}.db")


def setup_shards():
    for i in range(NUM_SHARDS):
        path = shard_path(i)
        if os.path.exists(path):
            os.remove(path)
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE users (user_id TEXT PRIMARY KEY, email TEXT, signup_country TEXT)")
        con.commit()
        con.close()


def write_user(user_id: str, email: str, country: str):
    """Route the write to the correct shard based on user_id (the shard key)."""
    shard_id = shard_for_key(user_id)
    con = sqlite3.connect(shard_path(shard_id))
    con.execute("INSERT INTO users VALUES (?, ?, ?)", (user_id, email, country))
    con.commit()
    con.close()
    return shard_id


def read_user(user_id: str):
    """A read for a known key only ever needs to hit ONE shard -- it doesn't
    need to scan every node, because the shard key deterministically tells
    you exactly where the row lives."""
    shard_id = shard_for_key(user_id)
    con = sqlite3.connect(shard_path(shard_id))
    row = con.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    con.close()
    return shard_id, row


def shard_distribution():
    counts = {}
    for i in range(NUM_SHARDS):
        con = sqlite3.connect(shard_path(i))
        n = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        con.close()
        counts[i] = n
    return counts


if __name__ == "__main__":
    setup_shards()

    users = [(f"user-{i}", f"user{i}@example.com", "ZA" if i % 3 == 0 else "US") for i in range(1, 21)]
    print(f"Writing {len(users)} users across {NUM_SHARDS} shards...")
    for user_id, email, country in users:
        shard_id = write_user(user_id, email, country)
        print(f"  {user_id} -> shard {shard_id}")

    print("\nShard distribution (should be roughly even):")
    print(" ", shard_distribution())

    print("\nReading 'user-7' (a single targeted lookup hits exactly one shard):")
    shard_id, row = read_user("user-7")
    print(f"  routed to shard {shard_id}, found: {row}")

    print("\nThis is exactly the mechanism behind Cassandra's partition key and")
    print("DynamoDB's partition key: the key you choose determines the write/read")
    print("path and the distribution of load across nodes -- a bad shard key")
    print("(e.g. sharding by signup_country here, with only 2 values) would send")
    print("all traffic to 2 of the 4 shards and leave the other 2 idle.")
