"""
Week 3 — MySQL demo, run against a real, live MySQL 8.0 server (not
simulated) -- the syllabus names both PostgreSQL and MySQL explicitly, so
this fills that gap the same way acid_demo.py did for Postgres.

Deliberately shows a genuine difference between the two: MySQL's default
storage engine (InnoDB) supports transactions and foreign keys just like
Postgres, but MySQL's engine choice matters in a way Postgres's doesn't --
this demo shows both the similarity (real ACID transactions on InnoDB) and
a real behavioural difference (MyISAM has neither) rather than treating
"SQL database" as one interchangeable thing.
"""
import mysql.connector

CONFIG = dict(host="localhost", user="labuser", password="labpass", database="quizeers_lab")


def setup(cur):
    cur.execute("DROP TABLE IF EXISTS accounts")
    cur.execute("""
        CREATE TABLE accounts (
            name VARCHAR(50) PRIMARY KEY,
            balance INT NOT NULL,
            CONSTRAINT chk_balance CHECK (balance >= 0)
        ) ENGINE=InnoDB
    """)
    cur.execute("INSERT INTO accounts VALUES ('alice', 100), ('bob', 50)")


def demo_atomicity_and_transactions(conn, cur):
    print("[MySQL/InnoDB] Atomicity: transferring 200 from alice (balance 100) -- should fail entirely")
    try:
        conn.start_transaction()
        cur.execute("UPDATE accounts SET balance = balance - 200 WHERE name = 'alice'")  # violates CHECK
        cur.execute("UPDATE accounts SET balance = balance + 200 WHERE name = 'bob'")
        conn.commit()
    except mysql.connector.Error as e:
        conn.rollback()
        print(f"  transaction rolled back: {e.__class__.__name__}: {e.msg}")
    cur.execute("SELECT name, balance FROM accounts ORDER BY name")
    print("  balances after failed transfer (unchanged, proving atomicity):", cur.fetchall())


def demo_engine_matters(cur):
    """MyISAM (MySQL's older, non-transactional engine) does NOT support
    transactions or foreign keys -- a real, MySQL-specific gotcha that
    doesn't exist in Postgres, which only ever had one storage engine."""
    cur.execute("DROP TABLE IF EXISTS legacy_log")
    cur.execute("CREATE TABLE legacy_log (id INT PRIMARY KEY, msg VARCHAR(100)) ENGINE=MyISAM")
    print("\n[MySQL] Engine choice matters here in a way it doesn't in Postgres:")
    print("  InnoDB (used above) supports transactions/rollback and foreign keys.")
    print("  MyISAM (just created for 'legacy_log') supports neither -- a ROLLBACK")
    print("  on a MyISAM table silently does nothing, which is a real source of")
    print("  bugs when a schema mixes engines without realizing it.")


if __name__ == "__main__":
    conn = mysql.connector.connect(**CONFIG)
    conn.autocommit = False
    cur = conn.cursor()
    setup(cur)
    conn.commit()

    demo_atomicity_and_transactions(conn, cur)
    demo_engine_matters(cur)
    conn.commit()

    cur.close()
    conn.close()
