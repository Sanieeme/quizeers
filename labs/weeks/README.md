# Week-by-Week Labs

This folder maps directly to the 9-week syllabus, filling the gaps
identified against the original `labs/` folder (which covered ETL, Spark,
Kafka, Airflow, and cloud topically rather than week-by-week). Each
week's README documents exactly what was run and verified vs. what's
reference-only, honestly, rather than claiming everything works
identically to production.

| Week | Folder | Headline gap(s) filled |
|---|---|---|
| 1 | `week01_intro/` | Real Jupyter notebook with auto-grading-style assertions |
| 2 | `week02_storage/` | Docker, measured CSV/JSON/Parquet comparison, CAP theorem simulation |
| 3 | `week03_dbms/` | Real Postgres (normalization, ACID), real ERD, sharding, DynamoDB, MongoDB |
| 4 | `week04_architecture_ingestion/` | Real REST API ingestion (GitHub), ETL vs EL vs ELT, BigQuery reference |
| 5 | `week05_processing/` | Real Apache Beam pipeline (the biggest single gap in the original pass) |
| 6 | `week06_governance/` | Governance framework, real data quality checks, 3 case studies |
| 7-8 | `week07_08_capstone/` | Full multi-source pipeline: Postgres CDC, SFTP, dbt, served REST API, Redis, Airflow |
| 9 | `week09_demo/` | Presentation/defense template (not code — see that folder's note) |

See `../README.md` for the original topic-based labs (ETL, Spark, Kafka,
Airflow, cloud, batch/stream) that these weeks build on and cross-reference.
