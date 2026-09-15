-- Mart: the kind of aggregate a served REST API endpoint would read from
-- directly (see ../api/serve.py's /api/revenue endpoint).
select
    country,
    source_system,
    sum(total_price) as revenue,
    count(*) as order_count
from {{ ref('mart_unified_orders') }}
group by country, source_system
order by revenue desc
