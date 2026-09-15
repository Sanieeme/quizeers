-- Mart: unions orders from two independent ingestion paths (real-time
-- SFTP drops and the original batch ETL pipeline) into one queryable
-- table -- this is the payoff of the capstone's multi-source design.
select * from {{ ref('stg_sftp_orders') }}
union all
select * from {{ ref('stg_batch_orders') }}
