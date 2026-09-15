"""
Week 4 — Ingesting data from a REST API using `requests`, the pattern named
in the syllabus for this week.

Hits the real GitHub REST API (api.github.com) -- not a mock. GitHub's
public API is unauthenticated-rate-limited (60 req/hour per IP), and this
sandbox's shared IP is often already at that limit, so this script
demonstrates the other half of real REST ingestion: handling rate limits
and transient failures gracefully instead of crashing the pipeline.
"""
import time
import requests

API_BASE = "https://api.github.com"
HEADERS = {"User-Agent": "data-engineering-labs", "Accept": "application/vnd.github+json"}


def fetch_repo(owner: str, repo: str, max_retries: int = 3) -> dict:
    """Extract step: GET a repo's metadata, with exponential backoff on
    rate limiting (HTTP 403 with an X-RateLimit-Remaining: 0 header) or
    transient server errors (5xx) -- the two failure modes a real REST
    ingestion job has to handle to not fall over on every API hiccup."""
    url = f"{API_BASE}/repos/{owner}/{repo}"

    for attempt in range(1, max_retries + 1):
        resp = requests.get(url, headers=HEADERS, timeout=10)

        if resp.status_code == 200:
            return resp.json()

        rate_limited = resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0"
        server_error = resp.status_code >= 500

        if (rate_limited or server_error) and attempt < max_retries:
            reset_at = resp.headers.get("X-RateLimit-Reset")
            wait = min(2 ** attempt, 5)  # capped exponential backoff for the demo
            reason = "rate limited" if rate_limited else f"server error {resp.status_code}"
            print(f"[extract] attempt {attempt} {reason}, retrying in {wait}s "
                  f"(reset_at={reset_at})...")
            time.sleep(wait)
            continue

        resp.raise_for_status()  # anything else (404, auth error, etc.) is a real failure

    raise RuntimeError(f"Failed to fetch {owner}/{repo} after {max_retries} attempts")


def transform_repo(raw: dict) -> dict:
    """Keep only the fields a downstream analytics table would actually want."""
    return {
        "full_name": raw.get("full_name"),
        "stars": raw.get("stargazers_count"),
        "forks": raw.get("forks_count"),
        "open_issues": raw.get("open_issues_count"),
        "language": raw.get("language"),
        "license": (raw.get("license") or {}).get("spdx_id"),
    }


def ingest_repos(repos: list) -> list:
    results = []
    for owner, repo in repos:
        try:
            raw = fetch_repo(owner, repo)
            results.append(transform_repo(raw))
            print(f"[ingest] {owner}/{repo}: OK")
        except Exception as e:
            print(f"[ingest] {owner}/{repo}: FAILED ({e.__class__.__name__}: {e})")
    return results


if __name__ == "__main__":
    repos = [("apache", "spark"), ("apache", "kafka"), ("apache", "airflow")]
    results = ingest_repos(repos)
    print("\n[load] would write these rows to the warehouse:")
    for row in results:
        print(" ", row)
