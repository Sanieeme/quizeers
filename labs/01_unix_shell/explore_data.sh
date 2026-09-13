#!/usr/bin/env bash
# 01_unix_shell/explore_data.sh
#
# A walkthrough of the core Unix/Linux commands a data engineer uses daily
# to inspect and sanity-check data files before they ever touch Python.
# Run with:  bash explore_data.sh
set -euo pipefail

DATA_FILE="../02_etl_pipeline/sample_data/orders_raw.csv"

echo "== File info (ls -lh) =="
ls -lh "$DATA_FILE"

echo -e "\n== Line count (wc -l) =="
wc -l "$DATA_FILE"

echo -e "\n== First 3 lines (head) =="
head -n 3 "$DATA_FILE"

echo -e "\n== Last 3 lines (tail) =="
tail -n 3 "$DATA_FILE"

echo -e "\n== Column headers (head -n 1 | tr) =="
head -n 1 "$DATA_FILE" | tr ',' '\n'

echo -e "\n== Rows mentioning 'South Africa' (grep) =="
grep "South Africa" "$DATA_FILE" || true

echo -e "\n== Count of rows per country (cut + sort + uniq -c) =="
tail -n +2 "$DATA_FILE" | cut -d',' -f8 | sort | uniq -c | sort -rn

echo -e "\n== Rows with an empty quantity field (awk) =="
awk -F',' 'NR>1 && $5==""' "$DATA_FILE" || true

echo -e "\n== Piping it all together: top product by row count =="
tail -n +2 "$DATA_FILE" | cut -d',' -f4 | sort | uniq -c | sort -rn | head -n 1
