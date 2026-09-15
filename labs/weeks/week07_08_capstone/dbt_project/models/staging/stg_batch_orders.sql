-- Staging model: the batch-ETL-sourced orders, cast to the same shape as
-- stg_sftp_orders so the two sources can be unioned in the mart below.
-- This is the real substance of multi-source integration: two pipelines
-- that never talk to each other still have to agree on a common shape.
select
    cast(order_id as varchar) as order_id,
    customer_name,
    product,
    cast(quantity as integer) as quantity,
    cast(unit_price as double) as unit_price,
    cast(total_price as double) as total_price,
    order_date,
    country,
    'batch_etl' as source_system
from raw_batch_orders
