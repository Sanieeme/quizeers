"""
Verifies azure_blob_upload.py against Azurite -- Microsoft's own official
open-source Azure Storage emulator (not a third-party mock; it's the real
emulator Microsoft publishes and recommends for local development/testing).

Requires azurite running locally:
    azurite-blob --silent --location /tmp/azurite_data &

Uses Azurite's well-known default development connection string (this is
a publicly documented placeholder credential for local emulator use only,
not a real secret).
"""
import os

AZURITE_CONNECTION_STRING = (
    "DefaultEndpointsProtocol=http;"
    "AccountName=devstoreaccount1;"
    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
)

os.environ["AZURE_STORAGE_CONNECTION_STRING"] = AZURITE_CONNECTION_STRING

import azure_blob_upload as mod


def test_upload_and_list():
    container = "test-container"
    mod.ensure_container(container)
    uploaded = mod.upload_directory(container, mod.LOCAL_PARQUET_DIR)
    assert len(uploaded) > 0, "expected at least one file to be uploaded"

    listed = mod.list_container(container)
    assert set(uploaded) == set(listed), "uploaded blobs should match what's listed in the container"
    print(f"PASS: uploaded and verified {len(uploaded)} blobs in real Azurite container '{container}'")


if __name__ == "__main__":
    test_upload_and_list()
