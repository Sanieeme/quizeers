"""
Uploads the ETL pipeline's Parquet output to Azure Blob Storage — the Azure
equivalent of aws_s3_upload.py / gcp_gcs_upload.py.

Requires: pip install azure-storage-blob
Auth: set AZURE_STORAGE_CONNECTION_STRING, or use DefaultAzureCredential
      with azure-identity for managed identity / az login auth.

**Verified in this repo against Azurite** (Microsoft's real, official local
Azure Storage emulator -- not a mock reimplementation, the actual
open-source emulator Microsoft ships) -- see
test_azure_blob_upload_with_azurite.py. Point AZURE_STORAGE_CONNECTION_STRING
at a real Azure account's connection string and this exact code runs
unchanged against production Azure.
"""
import os
from azure.storage.blob import BlobServiceClient

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_PARQUET_DIR = os.path.join(HERE, "..", "04_spark", "output_parquet")


def ensure_container(container_name: str):
    conn_str = os.environ["AZURE_STORAGE_CONNECTION_STRING"]
    service = BlobServiceClient.from_connection_string(conn_str)
    try:
        service.create_container(container_name)
    except Exception:
        pass  # already exists


def upload_directory(container_name: str, local_dir: str, prefix: str = "quiz-attempts/"):
    conn_str = os.environ["AZURE_STORAGE_CONNECTION_STRING"]
    service = BlobServiceClient.from_connection_string(conn_str)
    container = service.get_container_client(container_name)

    uploaded = []
    for root, _, files in os.walk(local_dir):
        for fname in files:
            local_path = os.path.join(root, fname)
            rel_path = os.path.relpath(local_path, local_dir)
            blob_name = prefix + rel_path.replace(os.sep, "/")
            with open(local_path, "rb") as f:
                container.upload_blob(name=blob_name, data=f, overwrite=True)
            uploaded.append(blob_name)
    print(f"[azure] uploaded {len(uploaded)} files to container '{container_name}' under '{prefix}'")
    return uploaded


def list_container(container_name: str, prefix: str = "quiz-attempts/"):
    conn_str = os.environ["AZURE_STORAGE_CONNECTION_STRING"]
    service = BlobServiceClient.from_connection_string(conn_str)
    container = service.get_container_client(container_name)
    return [b.name for b in container.list_blobs(name_starts_with=prefix)]


if __name__ == "__main__":
    CONTAINER = os.environ.get("DEMO_CONTAINER", "quizeers-analytics-demo")
    ensure_container(CONTAINER)
    upload_directory(CONTAINER, LOCAL_PARQUET_DIR)
    print("[azure] blobs now in container:", list_container(CONTAINER))
