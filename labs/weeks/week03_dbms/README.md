# Week 3 — Database Management Systems

## SQL fundamentals, ERDs, normalization, ACID — PostgreSQL

All run against a **real, live PostgreSQL 16** instance in this sandbox
(installed via apt, started, and connected to with psycopg2 — not simulated):

- `normalization_demo.py` — builds the same dataset as unnormalized, 1NF,
  2NF, and 3NF tables in real Postgres, and proves 3NF's payoff with an
  actual `UPDATE` that touches exactly one row instead of many.
- `acid_demo.py` — proves Atomicity (a failed multi-statement transfer
  rolls back completely), Consistency (a `CHECK` constraint rejects an
  invalid balance), and Isolation (a second connection can't see another
  connection's uncommitted write) against real transactions. Durability is
  explained rather than demonstrated, since proving it means killing the
  Postgres process mid-write.
- `generate_erd.py` — generates real ERD diagrams with Graphviz: one for
  the 3NF orders schema, and one for the Quizeers app's actual live schema
  (`erd_quizeers_schema.png`) — this is the real ERD for the app this
  whole project is built around.

## NoSQL: key-value, document, columnar, graph

- `dynamodb_demo.py` — **verified** against moto's mocked AWS. Real boto3
  DynamoDB calls: partition-key lookups (O(1)) vs. a full-table `scan`
  (the access-pattern trade-off DynamoDB forces you to design around).
- `mongodb_demo.py` — **verified** against mongomock, which reimplements
  the real pymongo API in-memory. Includes an actual MongoDB aggregation
  pipeline (`$unwind` / `$group`), not just `find()`.
- **Cassandra** (columnar/wide-column store) — genuinely attempted and
  confirmed infeasible in this sandbox, not just assumed: there is no
  Cassandra server package in Ubuntu's apt repos (only client libraries,
  e.g. `python3-cassandra`), and neither Apache Cassandra nor ScyllaDB
  (a Cassandra-protocol-compatible alternative) publish ready-to-run
  server binaries through any domain this sandbox's network allowlist
  permits — both are distributed via Docker images (Docker Hub is
  blocked here) or OS package repos outside the allowlist. The same
  partition-key routing concept Cassandra relies on is demonstrated
  concretely in `sharding_demo.py`.
- **Graph databases** (e.g. Neo4j) — covered conceptually in
  `../03_databases/nosql_demo.py` from the original labs set; not rebuilt
  here since it doesn't change with this deeper pass.

## SQL: PostgreSQL and MySQL

- **PostgreSQL** — see `normalization_demo.py` and `acid_demo.py` above.
- **MySQL** — `mysql_demo.py`, **run against a real, live MySQL 8.0**
  server (installed via apt). Deliberately shows a genuine MySQL-specific
  behavior that doesn't exist in Postgres: storage engine choice matters
  (InnoDB supports transactions and constraints; MyISAM silently doesn't),
  alongside proving the same real ACID transaction rollback Postgres
  demonstrated.

## Scalability: sharding

`sharding_demo.py` — a real, working sharding router across 4 separate
SQLite files (standing in for 4 separate DB nodes). Deterministically
routes writes/reads to one shard by hashing the shard key, and
demonstrates why shard key choice matters (a low-cardinality key like
"country" would concentrate all traffic on 2 of 4 nodes).

## What's genuinely tested vs. reference-only

| Component | Status |
|---|---|
| Postgres normalization + ACID | ✅ Real Postgres, actually run |
| MySQL transactions + engine behavior | ✅ Real MySQL 8.0, actually run |
| ERD diagrams | ✅ Real Graphviz output, rendered and inspected |
| Sharding | ✅ Real multi-file routing logic, run |
| DynamoDB | ✅ Real boto3 code, verified against moto |
| MongoDB | ✅ Real pymongo query syntax, verified against mongomock |
| Cassandra | ⚠️ Confirmed infeasible here — no server package reachable via any allowed domain (attempted Apache Cassandra and ScyllaDB; both only ship via Docker/repos outside this sandbox's allowlist) |
