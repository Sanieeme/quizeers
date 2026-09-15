# Apache Airflow lab

`dags/etl_dag.py` orchestrates the exact same Extract → Transform → Load
logic as `../02_etl_pipeline/`, wired up with Airflow scheduling, retries,
and explicit task dependencies (`extract >> transform >> load`).

## Why a separate virtual environment

Airflow 2.10 pins older versions of Flask, Werkzeug, and SQLAlchemy than
this repo's other labs (and than the Quizeers app) use. Rather than forcing
one dependency set on everything, install Airflow in its own venv:

```bash
python3 -m venv airflow_venv
airflow_venv/bin/pip install "apache-airflow==2.10.5" pandas \
  --constraint "https://raw.githubusercontent.com/apache/airflow/constraints-2.10.5/constraints-3.12.txt"
```

## Running it

```bash
export AIRFLOW_HOME=~/airflow_home
export AIRFLOW__CORE__DAGS_FOLDER=$(pwd)/dags   # points Airflow at this repo's DAG folder directly
export PATH=$(pwd)/../../airflow_venv/bin:$PATH  # adjust to wherever you created the venv

airflow db migrate
airflow standalone   # starts the scheduler + webserver, prints an admin password
```

Then open http://localhost:8080, log in as `admin`, unpause the `orders_etl`
DAG, and trigger a run — or test individual tasks from the CLI without the
webserver:

```bash
airflow tasks test orders_etl extract 2026-01-01
airflow tasks test orders_etl transform 2026-01-01
airflow tasks test orders_etl load 2026-01-01
```

This is exactly how the DAG was verified while building this repo: all
three tasks ran successfully through Airflow's real task engine and
produced the same warehouse output (7 valid orders, 3 rejected) as running
`02_etl_pipeline/pipeline.py` directly.
