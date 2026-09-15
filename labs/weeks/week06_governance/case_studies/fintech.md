# Case Study: FinTech

**Scenario:** A payments company processes millions of transactions daily
across multiple banking partners and card networks, and must reconcile
transaction records, detect fraud in near-real-time, and produce
regulator-ready financial reports.

**Data engineering challenges:**
- **Strict consistency requirements**: unlike many analytics use cases, a
  transaction ledger cannot tolerate eventual consistency — a CP-favoring
  system design (see the CAP theorem demo in Week 2) is often mandatory
  for the core ledger, even at some availability cost.
- **Low-latency stream processing**: fraud detection needs sub-second
  decisions on a stream of transaction events (Kafka + a stream processor
  like Flink or Kafka Streams), not a nightly batch job — this is the
  "Velocity" dimension of big data driving an architecture choice.
- **Auditability and immutability**: financial records typically use an
  append-only, event-sourced model (every state change is a new event,
  never an in-place update) so a complete audit trail exists — this maps
  directly to the CDC (Change Data Capture) pattern covered in the
  capstone: every change is captured as a discrete, ordered event.
- **Regulatory reporting**: data governance here isn't optional — the
  security and stewardship pillars are legally mandated (data
  residency rules, access logging, retention periods set by regulation
  rather than engineering preference).

**Relevant tools from this curriculum:** Kafka (transaction event stream),
a low-latency store for real-time fraud scoring (the same role Redis plays
in the capstone's high-velocity store), Spark or Flink for stream
processing, a data warehouse (BigQuery/Snowflake) for the batch-side
regulatory reports, and strict role-based access control at every layer.
