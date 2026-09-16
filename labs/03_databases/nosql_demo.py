"""
NoSQL (document store) demo using TinyDB, a pure-Python JSON document
database. The same query and access patterns shown here are what you'd use
against MongoDB in production -- TinyDB is used purely so this lab has no
external server dependency.

Key contrast with 03_databases/build_warehouse.py (relational/star schema):
- No fixed schema: each attempt document can have different fields.
- Related data is embedded (the per-question answers live inside the
  attempt) instead of being split across foreign-keyed tables.
- Great for irregular/nested/rapidly-changing data; harder to do ad-hoc
  cross-collection joins and aggregate reporting than in a warehouse.
"""
import os
from tinydb import TinyDB, Query

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "quiz_attempts_nosql.json")


def seed():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = TinyDB(DB_PATH)

    # Notice: attempt Q-1002 has an extra 'flagged_for_review' field and
    # attempt Q-1003 has more embedded answers than the others -- neither
    # would fit a fixed-width relational row without a schema change. A
    # document store handles this without migration.
    db.insert_multiple([
        {
            "attempt_id": "Q-1001",
            "user": {"name": "Alice Ng", "email": "alice@example.com"},
            "quiz_title": "Apache Kafka",
            "category": "Processing",
            "answers": [
                {"question": "What is a partition?", "correct": True},
                {"question": "What does a consumer group do?", "correct": True},
            ],
        },
        {
            "attempt_id": "Q-1002",
            "user": {"name": "Bob Smith", "email": "bob@example.com"},
            "quiz_title": "Relational Databases and SQL",
            "category": "Databases",
            "answers": [
                {"question": "What does a PRIMARY KEY enforce?", "correct": False},
            ],
            "flagged_for_review": True,
        },
        {
            "attempt_id": "Q-1003",
            "user": {"name": "Dana Lee", "email": "dana@example.com"},
            "quiz_title": "Apache Airflow",
            "category": "Orchestration",
            "answers": [
                {"question": "What is a DAG?", "correct": True},
                {"question": "What does a retry policy control?", "correct": True},
                {"question": "What does '@daily' schedule mean?", "correct": True},
            ],
        },
    ])
    return db


def demo_queries(db):
    Attempt = Query()

    print("[nosql] attempts in the 'Processing' category:")
    for a in db.search(Attempt.category == "Processing"):
        print(" -", a["attempt_id"], a["user"]["name"], "-", a["quiz_title"])

    print("\n[nosql] attempts with more than one answer recorded:")
    for a in db.search(Attempt.answers.test(lambda answers: len(answers) > 1)):
        print(" -", a["attempt_id"], f"({len(a['answers'])} answers)")

    print("\n[nosql] score per attempt (computed in app code, not SQL):")
    for a in db.all():
        correct = sum(1 for ans in a["answers"] if ans["correct"])
        total = len(a["answers"])
        score = (correct / total * 100) if total else 0
        print(f" - {a['attempt_id']}: {score:.2f}% ({correct}/{total})")


if __name__ == "__main__":
    db = seed()
    demo_queries(db)
