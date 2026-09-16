"""
Static catalog data describing the labs/ folder's contents, for the Labs
pages to render. This is data, not behaviour, so it doesn't belong mixed
into blueprints/labs.py's route functions.

`related_quiz_titles` is the link back to the quiz app: it holds the exact
`Quiz.title` value(s) (matching the "title" field in data/*.json) that each
lab is the hands-on counterpart to. blueprints/labs.py and
blueprints/quizzes.py both resolve these titles against the Quiz table to
build the actual cross-links shown in the templates -- so a lab can cover
more than one quiz (e.g. 03_databases backs three quizzes at once) and a
quiz can point back to more than one lab.
"""

LAB_CATALOG = [
    {
        "slug": "unix_shell",
        "title": "Unix / Linux Shell",
        "folder": "01_unix_shell",
        "description": "ls, grep, cut, awk, sort | uniq -c piped together to inspect a raw quiz-attempt log file from the command line.",
        "runnable": False,
        "related_quiz_titles": ["Data Engineering Basics"],
    },
    {
        "slug": "etl",
        "title": "ETL Pipeline",
        "folder": "02_etl_pipeline",
        "description": "A real Extract -> Transform -> Load pipeline in Pandas, run on a sample quiz-attempts log -- the same shape of pipeline analytics_etl/ runs for real against the live quiz database. Quarantines bad rows instead of dropping them silently.",
        "runnable": True,
        "related_quiz_titles": [
            "Data Engineering Basics",
            "Python for Data Engineering",
            "Data Storage and File Formats",
        ],
    },
    {
        "slug": "databases",
        "title": "Databases: Relational, NoSQL & Warehousing",
        "folder": "03_databases",
        "description": "A star schema (dim_user, dim_quiz, dim_date, fact_attempt) built from the ETL output -- the same pattern analytics_etl/ uses for the live app's Analytics dashboard -- plus a document-store (NoSQL) demo of the same quiz attempts for contrast.",
        "runnable": False,
        "related_quiz_titles": [
            "Relational Databases and SQL",
            "Non-Relational (NoSQL) Databases",
            "Data Warehousing and Data Architecture",
        ],
    },
    {
        "slug": "spark",
        "title": "Apache Spark",
        "folder": "04_spark",
        "description": "The same quiz-attempts ETL logic re-implemented with PySpark's DataFrame API, run in local cluster mode, writing Parquet partitioned by quiz category.",
        "runnable": False,
        "related_quiz_titles": ["Apache Spark", "Data Storage and File Formats"],
    },
    {
        "slug": "kafka",
        "title": "Apache Kafka",
        "folder": "05_kafka",
        "description": "Real producer/consumer scripts that stream quiz-attempt events to a live broker, plus a runnable broker-free simulation of topics, partitions, and consumer groups computing a running average score.",
        "runnable": False,
        "related_quiz_titles": ["Apache Kafka", "Data Ingestion Methods"],
    },
    {
        "slug": "airflow",
        "title": "Apache Airflow",
        "folder": "06_airflow",
        "description": "A real Airflow DAG (extract >> transform >> load) that runs the quiz-attempts ETL pipeline on a schedule with retries.",
        "runnable": False,
        "related_quiz_titles": ["Apache Airflow"],
    },
    {
        "slug": "cloud",
        "title": "Cloud: AWS, GCP, Azure",
        "folder": "07_cloud",
        "description": "Upload scripts that ship the quiz-attempts Parquet output to S3 / GCS / Blob Storage, verified against real emulators/mocks for all three providers.",
        "runnable": False,
        "related_quiz_titles": ["Cloud Platforms for Data Engineering (AWS, GCP, Azure)"],
    },
    {
        "slug": "batch_stream",
        "title": "Batch vs. Stream Processing",
        "folder": "08_batch_stream",
        "description": "Runs the same quiz-attempts data through a batch job and a simulated stream job side by side to make the trade-off concrete.",
        "runnable": False,
        "related_quiz_titles": ["Batch and Stream Processing"],
    },
]

WEEK_CATALOG = [
    {"week": "Week 1", "title": "Introduction to Data Engineering", "folder": "weeks/week01_intro",
     "description": "ETL pipeline as a Jupyter notebook with auto-grading-style assertions.",
     "related_quiz_titles": ["Data Engineering Basics"]},
    {"week": "Week 2", "title": "Data Storage and Virtualisation", "folder": "weeks/week02_storage",
     "description": "Measured CSV/JSON/Parquet comparison, CAP theorem simulation, Docker.",
     "related_quiz_titles": ["Data Storage and File Formats"]},
    {"week": "Week 3", "title": "Database Management Systems", "folder": "weeks/week03_dbms",
     "description": "Real Postgres & MySQL, a real ERD, sharding, DynamoDB, MongoDB.",
     "related_quiz_titles": ["Relational Databases and SQL", "Non-Relational (NoSQL) Databases"]},
    {"week": "Week 4", "title": "Data Architecture and Ingestion", "folder": "weeks/week04_architecture_ingestion",
     "description": "Real REST API ingestion, ETL vs EL vs ELT, warehouse vs. lake.",
     "related_quiz_titles": ["Data Ingestion Methods", "Data Warehousing and Data Architecture"]},
    {"week": "Week 5", "title": "Data Processing", "folder": "weeks/week05_processing",
     "description": "A real Apache Beam pipeline, plus links to the Spark/Kafka/Airflow labs.",
     "related_quiz_titles": ["Apache Spark", "Apache Kafka", "Apache Airflow", "Batch and Stream Processing"]},
    {"week": "Week 6", "title": "Data Governance and Real-World Applications", "folder": "weeks/week06_governance",
     "description": "Governance framework, real data quality checks, 3 industry case studies.",
     "related_quiz_titles": []},
    {"week": "Weeks 7-8", "title": "Capstone Project", "folder": "weeks/week07_08_capstone",
     "description": "Full multi-source pipeline: Postgres CDC, SFTP, dbt, a served REST API, Redis, orchestrated by Airflow.",
     "related_quiz_titles": ["Data Ingestion Methods", "Apache Airflow", "Cloud Platforms for Data Engineering (AWS, GCP, Azure)"]},
    {"week": "Week 9", "title": "Demo and Presentation", "folder": "weeks/week09_demo",
     "description": "A template for defending the capstone's architecture choices to reviewers.",
     "related_quiz_titles": []},
]
