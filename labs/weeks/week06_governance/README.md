# Week 6 — Data Governance and Real-World Applications

## Data governance: four pillars

1. **Quality** — is the data accurate, complete, and fit for use? See
   `data_quality_checks.py` (run and verified): implements the five
   standard data quality dimensions — completeness, uniqueness, validity,
   consistency, timeliness — as executable checks with numeric scores,
   not just definitions. On the sample dataset: 97.9% overall, with the
   one bad date and one missing quantity correctly flagged.
2. **Stewardship** — who is accountable for a dataset's definition,
   quality, and appropriate use? In `analytics_etl/` (built into the
   Quizeers app itself), the admin role is the de facto steward: only
   admins can trigger the ETL pipeline and view the resulting analytics,
   and the pipeline's source code documents exactly what each aggregate
   means and where it comes from.
3. **Security** — who can access what data? The Quizeers app already
   enforces this at the application layer: `@login_required` gates all
   quiz/lab access, `@admin_required` gates the analytics dashboard and
   user management, and the operational database
   (`quizeers.db`) is never exposed directly to end users — only through
   the app's own authenticated routes.
4. **Management** — the ongoing operational practice of maintaining all
   three of the above over time: versioning schema changes (e.g. adding
   `QuestionAttempt` required a migration path, not just a code change),
   documenting pipelines (every lab in this repo has a README explaining
   what it does and how it was verified), and deciding retention (e.g.
   how long raw `orders_raw.csv`-style source extracts should be kept
   before being purged from a lake).

## Data quality dimensions

Covered above — see `data_quality_checks.py`.

## Case studies

See `case_studies/` — three short write-ups on how these concepts play out
in FinTech, telecommunications, and legacy system integration.

## Docker labs

See `../week02_storage/Dockerfile` and its README section — Docker daemon
works in this sandbox, but image pulls from Docker Hub are blocked by the
network allowlist here, so the build itself wasn't completable in this
environment (documented honestly there rather than glossed over).

## Data cleaning with Pandas

Already the core of `../../02_etl_pipeline/transform.py` (run and
verified throughout this repo) plus the data quality checks above.
