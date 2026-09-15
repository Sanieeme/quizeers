"""
Week 3 — MongoDB demo using the real pymongo client API.

No real MongoDB server is available in this sandbox (its package repo
isn't reachable through the restricted network here), so this is tested
against mongomock -- a library that reimplements pymongo's actual API
in-memory, so the query code below is the real MongoDB query language,
not a stand-in. Point MongoClient at a real `mongodb://` URI and this
same code runs unchanged against a real cluster.
"""
import mongomock  # swap for `import pymongo` and a real connection string in production


def demo():
    client = mongomock.MongoClient()
    db = client["quizeers_lab"]
    orders = db["orders"]

    orders.insert_many([
        {
            "order_id": "A-1001",
            "customer": {"name": "Alice Ng", "country": "South Africa"},
            "items": [{"product": "Widget A", "qty": 3, "unit_price": 9.99}],
        },
        {
            "order_id": "A-1002",
            "customer": {"name": "Bob Smith", "country": "USA"},
            "items": [{"product": "Widget B", "qty": 1, "unit_price": 24.50}],
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

    print("[mongo] find orders from South Africa (dot notation into nested field):")
    for o in orders.find({"customer.country": "South Africa"}):
        print(" ", o["order_id"], o["customer"]["name"])

    print("\n[mongo] aggregation pipeline: total revenue per order")
    pipeline = [
        {"$unwind": "$items"},
        {"$project": {"order_id": 1, "line_total": {"$multiply": ["$items.qty", "$items.unit_price"]}}},
        {"$group": {"_id": "$order_id", "total": {"$sum": "$line_total"}}},
        {"$sort": {"_id": 1}},
    ]
    for row in orders.aggregate(pipeline):
        print(" ", row)

    print("\n[mongo] create an index on customer.country (as you would for a")
    print("  frequently-filtered field on a real, large collection):")
    orders.create_index("customer.country")
    print("  index list:", orders.index_information().keys())


if __name__ == "__main__":
    demo()
