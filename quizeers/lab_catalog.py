"""
Static catalog data describing the labs/ folder's contents, for the Labs
pages to render. This is data, not behaviour, so it doesn't belong mixed
into blueprints/labs.py's route functions.
"""

LAB_CATALOG = [
    {
        "slug": "unix_shell",
        "title": "Unix / Linux Shell",
        "folder": "01_unix_shell",
        "description": "ls, grep, cut, awk, sort | uniq -c piped together to inspect a raw data file from the command line.",
        "runnable": False,
    },
    {
        "slug": "etl",
        "title": "ETL Pipeline",
        "folder": "02_etl_pipeline",
        "description": "A real Extract -> Transform -> Load pipeline in Pandas. Quarantines bad rows instead of dropping them silently.",
        "runnable": True,
    },
    {
        "slug": "databases",
        "title": "Databases: Relational, NoSQL & Warehousing",
        "folder": "03_databases",
        "description": "A star schema (fact + dimension tables) built from the ETL output, plus a document-store (NoSQL) demo for contrast.",
        "runnable": False,
    },
    {
        "slug": "spark",
        "title": "Apache Spark",
        "folder": "04_spark",
        "description": "The same ETL logic re-implemented with PySpark's DataFrame API, run in local cluster mode, writing partitioned Parquet.",
        "runnable": False,
    },
    {
        "slug": "kafka",
        "title": "Apache Kafka",
        "folder": "05_kafka",
        "description": "Real producer/consumer scripts for a live broker, plus a runnable broker-free simulation of topics, partitions, and consumer groups.",
        "runnable": False,
    },
    {
        "slug": "airflow",
        "title": "Apache Airflow",
        "folder": "06_airflow",
        "description": "A real Airflow DAG (extract >> transform >> load) that runs the ETL pipeline on a schedule with retries.",
        "runnable": False,
    },
    {
        "slug": "cloud",
        "title": "Cloud: AWS, GCP, Azure",
        "folder": "07_cloud",
        "description": "Upload scripts for S3 / GCS / Blob Storage, verified against real emulators/mocks for all three providers.",
        "runnable": False,
    },
    {
        "slug": "batch_stream",
        "title": "Batch vs. Stream Processing",
        "folder": "08_batch_stream",
        "description": "Runs the same data through a batch job and a simulated stream job side by side to make the trade-off concrete.",
        "runnable": False,
    },
]

WEEK_CATALOG = [
    {"week": "Week 1", "title": "Introduction to Data Engineering", "folder": "weeks/week01_intro",
     "description": "ETL pipeline as a Jupyter notebook with auto-grading-style assertions."},
    {"week": "Week 2", "title": "Data Storage and Virtualisation", "folder": "weeks/week02_storage",
     "description": "Measured CSV/JSON/Parquet comparison, CAP theorem simulation, Docker."},
    {"week": "Week 3", "title": "Database Management Systems", "folder": "weeks/week03_dbms",
     "description": "Real Postgres & MySQL, a real ERD, sharding, DynamoDB, MongoDB."},
    {"week": "Week 4", "title": "Data Architecture and Ingestion", "folder": "weeks/week04_architecture_ingestion",
     "description": "Real REST API ingestion, ETL vs EL vs ELT, warehouse vs. lake."},
    {"week": "Week 5", "title": "Data Processing", "folder": "weeks/week05_processing",
     "description": "A real Apache Beam pipeline, plus links to the Spark/Kafka/Airflow labs."},
    {"week": "Week 6", "title": "Data Governance and Real-World Applications", "folder": "weeks/week06_governance",
     "description": "Governance framework, real data quality checks, 3 industry case studies."},
    {"week": "Weeks 7-8", "title": "Capstone Project", "folder": "weeks/week07_08_capstone",
     "description": "Full multi-source pipeline: Postgres CDC, SFTP, dbt, a served REST API, Redis, orchestrated by Airflow."},
    {"week": "Week 9", "title": "Demo and Presentation", "folder": "weeks/week09_demo",
     "description": "A template for defending the capstone's architecture choices to reviewers."},
]
