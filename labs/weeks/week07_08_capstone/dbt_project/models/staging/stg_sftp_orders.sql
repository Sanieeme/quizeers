-- Staging model: light cleaning of the raw SFTP-ingested orders, one row
-- of real transformation logic per source before anything gets combined.
select
    order_id,
    trim(customer_name) as customer_name,
    trim(product) as product,
    quantity,
    unit_price,
    round(quantity * unit_price, 2) as total_price,
    order_date,
    trim(country) as country,
    'sftp' as source_system
from raw_sftp_orders
