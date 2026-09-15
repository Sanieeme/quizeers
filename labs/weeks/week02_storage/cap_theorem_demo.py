"""
Week 2 — CAP theorem, made concrete with a tiny simulation.

CAP says a distributed data store can only guarantee two of three
properties at once when a network Partition happens:
  - Consistency:  every read sees the most recent write
  - Availability: every request gets a (non-error) response
  - Partition tolerance: the system keeps working despite network splits

Real distributed databases are forced to pick, e.g.:
  - PostgreSQL with synchronous replication: CP (refuses writes during a
    partition rather than risk inconsistency)
  - Cassandra / DynamoDB (default settings): AP (stays available during a
    partition, but replicas can briefly disagree -- "eventual consistency")

This script simulates a 2-node key-value store during a network partition
under both strategies, so the trade-off is visible rather than asserted.
"""
import copy


class Node:
    def __init__(self, name):
        self.name = name
        self.store = {}


class CPStore:
    """Consistency + Partition tolerance: refuses writes it can't
    replicate to both nodes, sacrificing Availability during a partition."""

    def __init__(self):
        self.nodes = [Node("A"), Node("B")]
        self.partitioned = False

    def write(self, key, value):
        if self.partitioned:
            return "REJECTED (no quorum -- refusing to risk inconsistency)"
        for n in self.nodes:
            n.store[key] = value
        return f"OK (written to both {[n.name for n in self.nodes]})"

    def read(self, node_index, key):
        return self.nodes[node_index].store.get(key, "<missing>")


class APStore:
    """Availability + Partition tolerance: always accepts writes/reads on
    whichever node it reaches, sacrificing Consistency during a partition."""

    def __init__(self):
        self.nodes = [Node("A"), Node("B")]
        self.partitioned = False

    def write(self, node_index, key, value):
        # writes to whichever node is reachable -- doesn't wait for the other
        self.nodes[node_index].store[key] = value
        return f"OK (written to node {self.nodes[node_index].name} only; will sync later)"

    def read(self, node_index, key):
        return self.nodes[node_index].store.get(key, "<missing>")


def demo():
    print("=== CP store (e.g. PostgreSQL w/ sync replication) during a partition ===")
    cp = CPStore()
    cp.partitioned = True
    print("write('inventory_count', 42):", cp.write("inventory_count", 42))
    print("  -> the write was REFUSED. The system chose Consistency over Availability.")

    print("\n=== AP store (e.g. Cassandra/DynamoDB defaults) during a partition ===")
    ap = APStore()
    ap.partitioned = True
    print("write to node A only:", ap.write(0, "inventory_count", 42))
    print("read from node A:", ap.read(0, "inventory_count"))
    print("read from node B:", ap.read(1, "inventory_count"), "<-- stale/missing: inconsistent!")
    print("  -> both reads succeeded (Available), but node B is out of date (not Consistent).")
    print("     Once the partition heals, the store reconciles B to match A ('eventual consistency').")


if __name__ == "__main__":
    demo()
