"""
Capstone — CDC (Change Data Capture) source: a real PostgreSQL table
(`inventory`) with a trigger that writes every INSERT/UPDATE/DELETE to a
`cdc_log` table, in order, with a monotonically increasing sequence number.

This is a genuine implementation of the *pattern* Debezium automates: in
production, Debezium reads Postgres's write-ahead log (WAL) directly via
logical replication, so it needs no triggers and no schema changes. A real
Debezium + Kafka Connect setup isn't installable in this sandbox (needs a
Kafka Connect worker and network access to Debezium's plugin distribution),
so this reimplements the same *outcome* — an ordered, complete log of every
change to a table — using a trigger-based approach that works with a plain
psycopg2 connection and is fully testable here.
"""
import psycopg2

CONN_STR = "dbname=quizeers_lab user=labuser password=labpass host=localhost"

DDL = """
DROP TABLE IF EXISTS cdc_log CASCADE;
DROP TABLE IF EXISTS inventory CASCADE;

CREATE TABLE inventory (
    sku TEXT PRIMARY KEY,
    product_name TEXT NOT NULL,
    quantity_on_hand INT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE cdc_log (
    log_id BIGSERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    op TEXT NOT NULL,               -- 'INSERT', 'UPDATE', or 'DELETE'
    sku TEXT NOT NULL,
    before_data JSONB,
    after_data JSONB,
    captured_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION inventory_cdc_trigger() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO cdc_log(table_name, op, sku, before_data, after_data)
        VALUES ('inventory', 'INSERT', NEW.sku, NULL, row_to_json(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO cdc_log(table_name, op, sku, before_data, after_data)
        VALUES ('inventory', 'UPDATE', NEW.sku, row_to_json(OLD), row_to_json(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO cdc_log(table_name, op, sku, before_data, after_data)
        VALUES ('inventory', 'DELETE', OLD.sku, row_to_json(OLD), NULL);
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER inventory_cdc
AFTER INSERT OR UPDATE OR DELETE ON inventory
FOR EACH ROW EXECUTE FUNCTION inventory_cdc_trigger();
"""


def setup():
    conn = psycopg2.connect(CONN_STR)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(DDL)
    print("[cdc] inventory + cdc_log tables and trigger created")
    cur.close()
    conn.close()


def simulate_source_activity():
    """Simulates an application writing to the source system over time --
    exactly the kind of activity a real OLTP app would generate, which CDC
    exists to capture without querying the app's database directly."""
    conn = psycopg2.connect(CONN_STR)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("INSERT INTO inventory (sku, product_name, quantity_on_hand) VALUES "
                "('SKU-001', 'Widget A', 100), ('SKU-002', 'Widget B', 50)")
    cur.execute("UPDATE inventory SET quantity_on_hand = 97 WHERE sku = 'SKU-001'")  # 3 sold
    cur.execute("INSERT INTO inventory (sku, product_name, quantity_on_hand) VALUES ('SKU-003', 'Widget C', 200)")
    cur.execute("UPDATE inventory SET quantity_on_hand = 45 WHERE sku = 'SKU-002'")  # 5 sold
    cur.execute("DELETE FROM inventory WHERE sku = 'SKU-003'")  # discontinued

    print("[cdc] simulated 5 source-system changes (2 inserts, 2 updates, 1 delete)")
    cur.close()
    conn.close()


if __name__ == "__main__":
    setup()
    simulate_source_activity()
