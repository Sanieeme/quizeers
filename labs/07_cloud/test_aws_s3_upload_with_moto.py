"""
Verifies aws_s3_upload.py's logic is correct using moto (a mocked AWS),
since this sandbox has no real AWS credentials. Run this to prove the S3
code works before pointing it at a real bucket with real credentials.
"""
import os
from moto import mock_aws
import aws_s3_upload as mod


@mock_aws
def test_upload_and_list():
    bucket = "test-bucket"
    mod.ensure_bucket(bucket)
    uploaded = mod.upload_directory(bucket, mod.LOCAL_PARQUET_DIR)
    assert len(uploaded) > 0, "expected at least one file to be uploaded"

    listed = mod.list_bucket(bucket)
    assert set(uploaded) == set(listed), "uploaded keys should match what's listed in the bucket"
    print(f"PASS: uploaded and verified {len(uploaded)} objects in mocked S3 bucket '{bucket}'")


if __name__ == "__main__":
    test_upload_and_list()
