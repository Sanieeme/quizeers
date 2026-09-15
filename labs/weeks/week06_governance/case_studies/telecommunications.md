# Case Study: Telecommunications

**Scenario:** A mobile network operator generates Call Detail Records
(CDRs) and network performance metrics from millions of devices
continuously — a genuinely high-Volume, high-Velocity data problem — and
needs this data for billing, network capacity planning, and customer churn
prediction.

**Data engineering challenges:**
- **Sheer volume**: a mid-sized carrier can generate billions of CDR
  events per day. This is squarely a Spark/distributed-processing problem
  (see Week 5) — no single machine, and often no single database, can
  hold or process this without horizontal scaling (see the sharding demo
  in Week 3 for the underlying partitioning mechanism at smaller scale).
- **Mixed batch and stream needs**: billing can tolerate a batch cycle
  (daily/monthly aggregation of usage), but network fault detection needs
  streaming (a cell tower going down should alert within seconds, not
  after the next batch run) — the same batch-vs-stream trade-off
  demonstrated in `../../08_batch_stream/`.
- **Data variety**: CDRs, network equipment logs, customer support
  tickets, and IoT sensor data from cell equipment all have different
  shapes and arrival patterns — this is the "Variety" dimension, and it's
  exactly why a data lake (schema-on-read, holds anything) often sits
  alongside a stricter warehouse for the cleaned, billing-relevant subset.
- **Long-tail data retention**: some data must be retained for years
  (regulatory call records) while other data (raw signal-strength
  telemetry) is only useful for hours — retention policy is a real
  governance ("Management" pillar) decision, not just a technical one.

**Relevant tools from this curriculum:** Spark for large-scale batch
aggregation, Kafka for real-time network event streams, a data lake (S3)
for raw heterogeneous data, a warehouse for billing-ready aggregates, and
Airflow to orchestrate the recurring batch billing cycle.
