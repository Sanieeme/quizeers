# Case Study: Legacy System Integration

**Scenario:** A large enterprise (common in insurance, government, and
manufacturing) still runs core operations on a decades-old mainframe or
on-prem system that can't be replaced quickly, but the business needs
modern analytics, a REST API for new applications, and real-time
visibility into data that currently only exists inside that legacy system.

**Data engineering challenges:**
- **No modern extraction interface**: legacy systems often expose data
  only through flat-file exports (fixed-width or delimited files dropped
  on a schedule), not an API. This is exactly the **SFTP ingestion**
  pattern in the capstone — a file lands on a server, and the pipeline
  polls for and pulls it, rather than an API being called.
- **CDC without native support**: many legacy databases don't have modern
  logical-replication CDC support the way Postgres does. In practice, this
  often means either (a) polling for changes via a `last_modified`
  timestamp column — the same technique demonstrated in the capstone's
  CDC emulator — or (b) parsing full daily extracts and diffing them
  against yesterday's snapshot to infer what changed.
- **Schema instability and undocumented meaning**: legacy fields are often
  named cryptically (`FLD_017`) with business meaning known only to a few
  long-tenured staff — this makes the "stewardship" governance pillar
  critical: someone has to own translating and documenting what the data
  actually means before it can be trusted downstream.
- **Risk-averse change management**: you often cannot modify the legacy
  system at all (no write access, fear of breaking a 30-year-old COBOL
  job), so all integration must be read-only and non-invasive — ingestion
  has to work around the system, not with it.

**Relevant tools from this curriculum:** SFTP/file-based ingestion, a
CDC/change-tracking mechanism built on top of timestamps or file diffing
rather than native database replication, a data lake to land raw legacy
extracts before any transformation, and thorough documentation/data
catalog work as the primary governance intervention.
