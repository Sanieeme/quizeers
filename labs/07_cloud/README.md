# Cloud: AWS, GCP, Azure

All three upload scripts follow the identical pattern (list local files,
upload each, list what landed) and all three are now **verified against
real emulators or mocks** — not left as unverified reference code:

| Provider | Script | Verified against |
|---|---|---|
| AWS | `aws_s3_upload.py` | moto (mocked AWS) — `test_aws_s3_upload_with_moto.py` |
| GCP | `gcp_gcs_upload.py` | `gcp-storage-emulator` (a real local server implementing the actual GCS JSON API) — `test_gcs_upload_with_emulator.py` |
| Azure | `azure_blob_upload.py` | Azurite (Microsoft's own official local Azure Storage emulator) — `test_azure_blob_upload_with_azurite.py` |

Run any of the three test files directly to see it pass:

```bash
python3 test_aws_s3_upload_with_moto.py
python3 test_gcs_upload_with_emulator.py

# Azurite needs to be running first:
azurite-blob --silent --location /tmp/azurite_data &
python3 test_azure_blob_upload_with_azurite.py
```

Each production script auto-detects whether it's talking to an
emulator/mock or the real cloud (via environment variables it already
reads for credentials/emulator hosts), so no code changes are needed to
point any of them at a real account — only credentials.
