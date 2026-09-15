"""
Uploads the ETL pipeline's Parquet output (from 04_spark) to an S3 bucket,
and reads it back — the pattern used to hand data off between pipeline
stages or to downstream consumers (Redshift Spectrum, Athena, another team).

Uses real boto3 calls, so it works unmodified against real AWS given
credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / a configured
profile). This lab's automated test runs it against moto's mocked S3, since
no real AWS account is available in this sandbox.
"""
import os
import boto3

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_PARQUET_DIR = os.path.join(HERE, "..", "04_spark", "output_parquet")


def upload_directory(bucket: str, local_dir: str, prefix: str = "orders/"):
    s3 = boto3.client("s3")
    uploaded = []
    for root, _, files in os.walk(local_dir):
        for fname in files:
            local_path = os.path.join(root, fname)
            rel_path = os.path.relpath(local_path, local_dir)
            key = prefix + rel_path.replace(os.sep, "/")
            s3.upload_file(local_path, bucket, key)
            uploaded.append(key)
    print(f"[s3] uploaded {len(uploaded)} files to s3://{bucket}/{prefix}")
    return uploaded


def list_bucket(bucket: str, prefix: str = "orders/"):
    s3 = boto3.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    keys = [obj["Key"] for obj in resp.get("Contents", [])]
    return keys


def ensure_bucket(bucket: str, region: str = "us-east-1"):
    s3 = boto3.client("s3", region_name=region)
    existing = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    if bucket not in existing:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
        print(f"[s3] created bucket {bucket}")


if __name__ == "__main__":
    BUCKET = os.environ.get("DEMO_BUCKET", "data-engineering-labs-demo")
    ensure_bucket(BUCKET)
    upload_directory(BUCKET, LOCAL_PARQUET_DIR)
    print("[s3] objects now in bucket:", list_bucket(BUCKET))
