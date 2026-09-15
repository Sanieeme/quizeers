"""
Week 3 — ACID properties, demonstrated against a real Postgres connection
rather than just defined.
"""
import psycopg2

CONN_STR = "dbname=quizeers_lab user=labuser password=labpass host=localhost"


def setup(cur):
    cur.execute("DROP TABLE IF EXISTS accounts")
    cur.execute("CREATE TABLE accounts (name TEXT PRIMARY KEY, balance INT NOT NULL CHECK (balance >= 0))")
    cur.execute("INSERT INTO accounts VALUES ('alice', 100), ('bob', 50)")


def demo_atomicity(conn):
    """A multi-statement transfer either fully happens or not at all."""
    cur = conn.cursor()
    print("[Atomicity] Transferring 200 from alice (balance 100) to bob -- should fail entirely")
    try:
        cur.execute("BEGIN")
        cur.execute("UPDATE accounts SET balance = balance - 200 WHERE name = 'alice'")  # would violate CHECK
        cur.execute("UPDATE accounts SET balance = balance + 200 WHERE name = 'bob'")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  transaction rolled back: {e.__class__.__name__}")
    cur.execute("SELECT name, balance FROM accounts ORDER BY name")
    print("  balances after failed transfer (unchanged, proving atomicity):", cur.fetchall())


def demo_consistency(conn):
    """The CHECK constraint enforces a business rule -- balance can't go negative."""
    cur = conn.cursor()
    print("\n[Consistency] Trying to force alice's balance negative directly")
    try:
        cur.execute("UPDATE accounts SET balance = -5 WHERE name = 'alice'")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  rejected by the CHECK constraint: {e.__class__.__name__}")


def demo_isolation(conn):
    """Two concurrent connections don't see each other's uncommitted writes."""
    conn2 = psycopg2.connect(CONN_STR)
    cur1, cur2 = conn.cursor(), conn2.cursor()
    print("\n[Isolation] Connection 1 starts a transaction but doesn't commit yet")
    cur1.execute("BEGIN")
    cur1.execute("UPDATE accounts SET balance = balance + 1000 WHERE name = 'alice'")
    cur2.execute("SELECT balance FROM accounts WHERE name = 'alice'")
    print("  connection 2 sees (uncommitted change is invisible):", cur2.fetchone())
    conn.commit()
    cur2.execute("SELECT balance FROM accounts WHERE name = 'alice'")
    print("  connection 2 sees after commit:", cur2.fetchone())
    conn2.close()


def demo_durability(conn):
    print("\n[Durability] Once COMMIT returns, Postgres has fsynced the change to WAL on disk --")
    print("  a crash immediately after commit would NOT lose this write on restart.")
    print("  (Not simulated here since it requires actually killing the postgres process --")
    print("  this is what write-ahead logging exists to guarantee.)")


if __name__ == "__main__":
    conn = psycopg2.connect(CONN_STR)
    conn.autocommit = False
    cur = conn.cursor()
    setup(cur)
    conn.commit()

    demo_atomicity(conn)
    demo_consistency(conn)
    demo_isolation(conn)
    demo_durability(conn)

    cur.close()
    conn.close()
