# Week 2 — Data Storage and Virtualisation

## Computing hardware & storage units / transfer rates

The basics: bit → byte → KB → MB → GB → TB → PB (powers of 1024, not 1000,
when referring to actual memory/disk addressing — "1 GB" of RAM is 2^30
bytes, though storage vendors often market in decimal GB = 10^9 bytes,
which is why a "1 TB" drive shows as ~931 GiB in your OS).

Transfer rate matters for pipeline design: reading 100 GB from local NVMe
SSD (~3,500 MB/s) takes seconds; the same 100 GB over a 100 Mbps network
link (~12.5 MB/s) takes over two hours. This is why data locality (running
compute where the data already lives — the whole idea behind Hadoop/HDFS
and Spark's cluster model) matters at scale.

## Structured vs. unstructured formats: CSV, JSON, Parquet

See `compare_file_formats.py` — actually measured on this machine, not
asserted:

| Format  | Size (20k rows) | Write | Read | Read 1 column only |
|---|---|---|---|---|
| CSV     | 1,327 KB | 0.055s | 0.053s | 0.019s (parses every column anyway) |
| JSON    | 3,370 KB | 0.038s | 0.059s | — |
| Parquet | 123 KB   | 0.066s | 0.029s | 0.002s (columnar — skips the rest) |

Parquet is ~10x smaller and ~8x faster for single-column analytical reads,
which is exactly the access pattern a warehouse query does ("give me just
the `country` and `revenue` columns from a 50-column table").

## Distributed file systems: HDFS, S3, GCS

**Not runnable here** — a real HDFS cluster needs a NameNode + DataNode
Java processes and isn't installable via this sandbox's restricted package
mirror. Conceptually, though, the pattern is the same across all three:

- **HDFS**: splits files into fixed-size blocks (default 128 MB), replicates
  each block across multiple DataNodes (default 3x), and a NameNode tracks
  which blocks live where. Designed to run on commodity hardware in your
  own data center.
- **S3 / GCS**: the cloud-managed equivalent — you get the same
  "durable, replicated, massively scalable object storage" property
  without operating the NameNode/DataNode processes yourself. See
  `../07_cloud/aws_s3_upload.py` (tested against mocked S3 in this repo) and
  `gcp_gcs_upload.py`.

The throughline: don't store 128 MB blocks on one disk if you need
petabyte scale and fault tolerance — split and replicate, and let the
compute framework (Hadoop MapReduce, Spark) schedule work close to
wherever the data blocks actually live.

## CAP theorem

See `cap_theorem_demo.py` — actually run, output above. Simulates a 2-node
store during a network partition under both a CP strategy (rejects writes
to stay consistent) and an AP strategy (stays available, briefly
inconsistent, reconciles later).

## Cloud storage models

- **Object storage** (S3, GCS, Azure Blob): flat namespace of key→blob,
  accessed over HTTP, no filesystem semantics (no "directories" really —
  just keys with `/` in the name). Best for large, immutable files: Parquet
  data lake files, backups, static assets.
- **Block storage** (EBS, Persistent Disk): behaves like a raw disk
  attached to one VM. Needed when a database needs low-latency random
  read/write, like a live Postgres instance's data directory.
- **File storage** (EFS, Filestore): a traditional shared filesystem (NFS)
  multiple machines can mount at once. Used less in modern data platforms,
  but still shows up for legacy app compatibility.

## Docker containerisation

`Dockerfile` containerises the Week 1 ETL pipeline. **Genuinely attempted
end-to-end, confirmed partially blocked, not just assumed:**
- The Docker daemon itself **does run** in this sandbox (confirmed:
  `dockerd` starts and `docker info`/`docker build` execute).
- `docker build` fails at the `FROM python:3.12-slim` layer with a 403
  from `registry-1.docker.io` — this sandbox's network allowlist has no
  container registry on it at all (checked: neither Docker Hub nor GitHub
  Container Registry are reachable).
- As a second attempt, building a base image locally via `docker import`
  from this sandbox's own root filesystem (avoiding any registry
  entirely) was tried and hit a **disk quota limit** (~5GB available,
  a full rootfs tarball exceeded it) before completing — documented here
  rather than silently abandoned.
- The Dockerfile itself follows standard practice (pin base image, install
  deps before copying code for layer caching, single-purpose CMD) and
  would build normally in an unrestricted environment —
  `docker build -t etl-pipeline .` followed by `docker run --rm etl-pipeline`.
