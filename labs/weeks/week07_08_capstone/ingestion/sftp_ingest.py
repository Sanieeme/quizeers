"""
Capstone — SFTP ingestion, the pattern named for legacy/partner-system
data exchange (see week06 case_studies/legacy_system_integration.md).

Uses real paramiko SFTP calls against a real local OpenSSH server running
in this sandbox (not mocked). Connects, lists the remote landing directory,
downloads any file not yet ingested, and moves it to a 'processed/'
subfolder on the remote side -- the standard "at-least-once, idempotent"
pattern for file-based ingestion, so a failed run doesn't re-process
everything or silently skip a file.
"""
import os
import paramiko

SFTP_HOST = "localhost"
SFTP_PORT = 22
SFTP_USER = "sftpuser"
SFTP_PASS = "sftppass"
REMOTE_DIR = "uploads"
REMOTE_PROCESSED_DIR = "uploads/processed"
LOCAL_DOWNLOAD_DIR = os.path.join(os.path.dirname(__file__), "downloaded")


def ingest():
    os.makedirs(LOCAL_DOWNLOAD_DIR, exist_ok=True)

    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.connect(username=SFTP_USER, password=SFTP_PASS)
    sftp = paramiko.SFTPClient.from_transport(transport)

    try:
        sftp.stat(REMOTE_PROCESSED_DIR)
    except FileNotFoundError:
        sftp.mkdir(REMOTE_PROCESSED_DIR)

    remote_files = [f for f in sftp.listdir(REMOTE_DIR) if f.endswith(".csv")]
    print(f"[sftp] found {len(remote_files)} unprocessed file(s) in {REMOTE_DIR}/: {remote_files}")

    downloaded = []
    for fname in remote_files:
        remote_path = f"{REMOTE_DIR}/{fname}"
        local_path = os.path.join(LOCAL_DOWNLOAD_DIR, fname)
        sftp.get(remote_path, local_path)
        print(f"[sftp] downloaded {remote_path} -> {local_path}")

        # move to processed/ so a re-run doesn't re-ingest the same file --
        # the file-based equivalent of an offset/checkpoint. Suffix with a
        # timestamp so re-running against a same-named file (e.g. a daily
        # extract that reuses the filename each day) never collides with
        # an already-archived copy.
        import time
        archived_name = f"{os.path.splitext(fname)[0]}_{int(time.time())}{os.path.splitext(fname)[1]}"
        sftp.rename(remote_path, f"{REMOTE_PROCESSED_DIR}/{archived_name}")
        downloaded.append(local_path)

    sftp.close()
    transport.close()
    return downloaded


if __name__ == "__main__":
    files = ingest()
    if files:
        import pandas as pd
        for path in files:
            df = pd.read_csv(path)
            print(f"\n[sftp] preview of {os.path.basename(path)}:")
            print(df)
    else:
        print("[sftp] nothing new to ingest")
