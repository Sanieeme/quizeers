"""
NoSQL (document store) demo using TinyDB, a pure-Python JSON document
database. The same query and access patterns shown here are what you'd use
against MongoDB in production — TinyDB is used purely so this lab has no
external server dependency.

Key contrast with 03_databases/build_warehouse.py (relational/star schema):
- No fixed schema: each order document can have different fields.
- Related data is embedded (line items live inside the order) instead of
  being split across foreign-keyed tables.
- Great for irregular/nested/rapidly-changing data; harder to do ad-hoc
  cross-collection joins and aggregate reporting than in a warehouse.
"""
import os
from tinydb import TinyDB, Query

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "orders_nosql.json")


def seed():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = TinyDB(DB_PATH)

    # Notice: order 2 has an extra 'gift_wrap' field and order 3 has multiple
    # line items — neither would fit a fixed-width relational row without
    # a schema change. A document store handles this without migration.
    db.insert_multiple([
        {
            "order_id": "A-1001",
            "customer": {"name": "Alice Ng", "country": "South Africa"},
            "items": [{"product": "Widget A", "qty": 3, "unit_price": 9.99}],
        },
        {
            "order_id": "A-1002",
            "customer": {"name": "Bob Smith", "country": "USA"},
            "items": [{"product": "Widget B", "qty": 1, "unit_price": 24.50}],
            "gift_wrap": True,
        },
        {
            "order_id": "A-1003",
            "customer": {"name": "Dana Lee", "country": "South Africa"},
            "items": [
                {"product": "Widget C", "qty": 5, "unit_price": 4.25},
                {"product": "Widget A", "qty": 2, "unit_price": 9.99},
            ],
        },
    ])
    return db


def demo_queries(db):
    Order = Query()

    print("[nosql] orders from South Africa:")
    for o in db.search(Order.customer.country == "South Africa"):
        print(" -", o["order_id"], o["customer"]["name"])

    print("\n[nosql] orders with more than one line item:")
    for o in db.search(Order.items.test(lambda items: len(items) > 1)):
        print(" -", o["order_id"], f"({len(o['items'])} items)")

    print("\n[nosql] total revenue per order (computed in app code, not SQL):")
    for o in db.all():
        total = sum(i["qty"] * i["unit_price"] for i in o["items"])
        print(f" - {o['order_id']}: {total:.2f}")


if __name__ == "__main__":
    db = seed()
    demo_queries(db)
