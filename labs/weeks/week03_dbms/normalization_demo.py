"""
Week 3 — Normalization walkthrough (1NF -> 2NF -> 3NF), run against a real
PostgreSQL database (not simulated) to show the anomalies normalization
fixes, not just define the rules.

Requires a running Postgres reachable at the connection string below.
"""
import psycopg2

CONN_STR = "dbname=quizeers_lab user=labuser password=labpass host=localhost"


def reset(cur):
    cur.execute("""
        DROP TABLE IF EXISTS orders_unnormalized;
        DROP TABLE IF EXISTS orders_1nf;
        DROP TABLE IF EXISTS orders_2nf_line_items;
        DROP TABLE IF EXISTS orders_2nf;
        DROP TABLE IF EXISTS customers_3nf CASCADE;
        DROP TABLE IF EXISTS orders_3nf CASCADE;
        DROP TABLE IF EXISTS order_items_3nf;
    """)


def unnormalized(cur):
    # Violates 1NF: the 'products' column holds multiple values in one
    # cell (a comma-separated list) instead of one value per cell.
    cur.execute("""
        CREATE TABLE orders_unnormalized (
            order_id INT,
            customer_name TEXT,
            customer_city TEXT,
            products TEXT   -- e.g. 'Widget A x3, Widget B x1'  <-- 1NF violation
        )
    """)
    cur.execute("""
        INSERT INTO orders_unnormalized VALUES
        (1, 'Alice Ng', 'Johannesburg', 'Widget A x3, Widget B x1'),
        (2, 'Bob Smith', 'New York', 'Widget C x2')
    """)
    print("[unnormalized] one row can hide multiple facts in a single cell -- "
          "you can't easily ask 'how many Widget A have we sold total?' with SQL")


def first_normal_form(cur):
    # 1NF fix: one product per row (atomic values, no repeating groups)
    cur.execute("""
        CREATE TABLE orders_1nf (
            order_id INT,
            customer_name TEXT,
            customer_city TEXT,
            product TEXT,
            quantity INT
        )
    """)
    cur.execute("""
        INSERT INTO orders_1nf VALUES
        (1, 'Alice Ng', 'Johannesburg', 'Widget A', 3),
        (1, 'Alice Ng', 'Johannesburg', 'Widget B', 1),
        (2, 'Bob Smith', 'New York', 'Widget C', 2)
    """)
    print("[1NF] atomic values now -- but customer_name/customer_city repeat "
          "for every line item of the same order (update anomaly risk: fixing "
          "a typo in Alice's city means updating it in 2 places)")


def second_normal_form(cur):
    # 2NF fix: split out data that depends on only PART of the composite
    # key (order_id, product) -- customer info depends only on order_id,
    # not on the product, so it doesn't belong on the line-item table.
    cur.execute("""
        CREATE TABLE orders_2nf (
            order_id INT PRIMARY KEY,
            customer_name TEXT,
            customer_city TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE orders_2nf_line_items (
            order_id INT REFERENCES orders_2nf(order_id),
            product TEXT,
            quantity INT,
            PRIMARY KEY (order_id, product)
        )
    """)
    cur.execute("INSERT INTO orders_2nf VALUES (1, 'Alice Ng', 'Johannesburg'), (2, 'Bob Smith', 'New York')")
    cur.execute("""
        INSERT INTO orders_2nf_line_items VALUES
        (1, 'Widget A', 3), (1, 'Widget B', 1), (2, 'Widget C', 2)
    """)
    print("[2NF] customer info no longer repeats per line item -- but "
          "customer_city is stored per-order, and if a customer places two "
          "orders, their city is duplicated across both order rows")


def third_normal_form(cur):
    # 3NF fix: remove transitive dependencies. customer_city depends on
    # the customer, not directly on the order -- so it belongs on a
    # separate customers table, not the orders table.
    cur.execute("""
        CREATE TABLE customers_3nf (
            customer_id SERIAL PRIMARY KEY,
            customer_name TEXT UNIQUE,
            customer_city TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE orders_3nf (
            order_id INT PRIMARY KEY,
            customer_id INT REFERENCES customers_3nf(customer_id)
        )
    """)
    cur.execute("""
        CREATE TABLE order_items_3nf (
            order_id INT REFERENCES orders_3nf(order_id),
            product TEXT,
            quantity INT,
            PRIMARY KEY (order_id, product)
        )
    """)
    cur.execute("""
        INSERT INTO customers_3nf (customer_name, customer_city)
        VALUES ('Alice Ng', 'Johannesburg'), ('Bob Smith', 'New York')
        RETURNING customer_id
    """)
    ids = [row[0] for row in cur.fetchall()]
    cur.execute("INSERT INTO orders_3nf VALUES (1, %s), (2, %s)", (ids[0], ids[1]))
    cur.execute("""
        INSERT INTO order_items_3nf VALUES
        (1, 'Widget A', 3), (1, 'Widget B', 1), (2, 'Widget C', 2)
    """)
    print("[3NF] customer_city now lives in exactly one place -- updating "
          "Alice's city updates it everywhere she's referenced, with zero "
          "duplicate data and no update anomalies")


def prove_it(cur):
    print("\n--- Proof: updating a customer's city in 3NF touches exactly one row ---")
    cur.execute("UPDATE customers_3nf SET customer_city = 'Cape Town' WHERE customer_name = 'Alice Ng'")
    cur.execute("""
        SELECT o.order_id, c.customer_name, c.customer_city
        FROM orders_3nf o JOIN customers_3nf c ON c.customer_id = o.customer_id
        WHERE c.customer_name = 'Alice Ng'
    """)
    for row in cur.fetchall():
        print(" ", row)
    print("(In the unnormalized/1NF versions, this update would need to touch "
          "every line-item row for every order Alice ever placed.)")


if __name__ == "__main__":
    conn = psycopg2.connect(CONN_STR)
    conn.autocommit = True
    cur = conn.cursor()
    reset(cur)
    unnormalized(cur)
    first_normal_form(cur)
    second_normal_form(cur)
    third_normal_form(cur)
    prove_it(cur)
    cur.close()
    conn.close()
