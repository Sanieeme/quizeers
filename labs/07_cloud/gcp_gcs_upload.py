"""
Uploads the ETL pipeline's Parquet output to Google Cloud Storage — the GCP
equivalent of aws_s3_upload.py.

Requires: pip install google-cloud-storage
Auth: gcloud auth application-default login, or GOOGLE_APPLICATION_CREDENTIALS
      pointing at a service account key.

**Verified in this repo against a real GCS emulator** (gcp-storage-emulator,
a Python package that runs an actual local server implementing the GCS
JSON API, not a hand-rolled mock) -- see test_gcs_upload_with_emulator.py.
Unset STORAGE_EMULATOR_HOST to run this unchanged against real GCP.
"""
import os
from google.cloud import storage

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_PARQUET_DIR = os.path.join(HERE, "..", "04_spark", "output_parquet")


def get_client():
    if os.environ.get("STORAGE_EMULATOR_HOST"):
        # the emulator doesn't check real credentials -- anonymous client
        return storage.Client.create_anonymous_client()
    return storage.Client()


def ensure_bucket(bucket_name: str):
    client = get_client()
    try:
        client.create_bucket(bucket_name)
    except Exception:
        pass  # already exists


def upload_directory(bucket_name: str, local_dir: str, prefix: str = "orders/"):
    client = get_client()
    bucket = client.bucket(bucket_name)
    uploaded = []
    for root, _, files in os.walk(local_dir):
        for fname in files:
            local_path = os.path.join(root, fname)
            rel_path = os.path.relpath(local_path, local_dir)
            blob_name = prefix + rel_path.replace(os.sep, "/")
            bucket.blob(blob_name).upload_from_filename(local_path)
            uploaded.append(blob_name)
    print(f"[gcs] uploaded {len(uploaded)} files to gs://{bucket_name}/{prefix}")
    return uploaded


def list_bucket(bucket_name: str, prefix: str = "orders/"):
    client = get_client()
    return [b.name for b in client.list_blobs(bucket_name, prefix=prefix)]


if __name__ == "__main__":
    BUCKET = os.environ.get("DEMO_BUCKET", "data-engineering-labs-demo")
    ensure_bucket(BUCKET)
    upload_directory(BUCKET, LOCAL_PARQUET_DIR)
    print("[gcs] objects now in bucket:", list_bucket(BUCKET))
