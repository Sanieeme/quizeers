-- ClickHouse schema for high-velocity event store
-- Database and table optimized for fast inserts and real-time queries

CREATE DATABASE IF NOT EXISTS analytics;

CREATE TABLE IF NOT EXISTS analytics.events
(
    event_id UUID,
    user_id UInt64,
    event_type String,
    payload String, -- JSON string; ClickHouse can parse JSON at query time if needed
    ts DateTime64(3),
    op String,      -- operation type for CDC (insert/update/delete)
    version UInt64  -- monotonic version for ReplacingMergeTree
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(ts)
ORDER BY (user_id, ts, event_id);

-- Notes:
-- 1) Use batching and the native ClickHouse client for high-throughput writes.
-- 2) Consider TTL policies or separate cold storage (S3) for older partitions.
-- 3) For multi-row idempotency, include a `version` column from CDC stream to drive ReplacingMergeTree.
-- 4) To support point-in-time queries, maintain a small audit table or use MergeTree settings to keep history.
