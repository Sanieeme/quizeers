-- Staging model for the current inventory state, sourced from Postgres via
-- the CDC pipeline in ../../cdc/ (the trigger-based change log applied to
-- the source-of-truth `inventory` table, then loaded raw here by
-- load_raw_sources.py).
select
    sku,
    trim(product_name) as product_name,
    quantity_on_hand,
    updated_at
from raw_inventory
