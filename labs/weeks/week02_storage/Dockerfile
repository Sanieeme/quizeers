# Week 2 — Docker containerisation of the ETL pipeline.
#
# Build:  docker build -t etl-pipeline .
# Run:    docker run --rm etl-pipeline
#
# No Docker daemon is available in the sandbox this repo was built in
# (confirmed: `docker` is not installed there), so this file is reviewed
# and syntax-checked but not built-and-run here. It follows standard
# multi-stage-free best practice for a small Python job: pin the base
# image, install deps first for layer caching, copy code last.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY extract.py transform.py load.py pipeline.py ./
COPY sample_data ./sample_data

# Runs the pipeline once and exits — this is a batch job, not a server,
# so there's no long-running process or exposed port needed.
CMD ["python3", "pipeline.py"]
