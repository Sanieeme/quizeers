"""
Verifies gcp_gcs_upload.py against a real GCS emulator (gcp-storage-emulator
package) -- an actual local server implementing the GCS JSON API, started
in-process here, not a hand-rolled mock.
"""
import os
from gcp_storage_emulator.server import create_server

HOST, PORT = "localhost", 9023
os.environ["STORAGE_EMULATOR_HOST"] = f"http://{HOST}:{PORT}"

import gcp_gcs_upload as mod


def test_upload_and_list():
    server = create_server(HOST, PORT, in_memory=True, default_bucket=None)
    server.start()
    try:
        bucket = "test-bucket"
        mod.ensure_bucket(bucket)
        uploaded = mod.upload_directory(bucket, mod.LOCAL_PARQUET_DIR)
        assert len(uploaded) > 0, "expected at least one file to be uploaded"

        listed = mod.list_bucket(bucket)
        assert set(uploaded) == set(listed), "uploaded blobs should match what's listed"
        print(f"PASS: uploaded and verified {len(uploaded)} objects in real GCS-emulator bucket '{bucket}'")
    finally:
        server.stop()


if __name__ == "__main__":
    test_upload_and_list()
