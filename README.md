quizeers_app

WTC-SHVZT25U 


## Quiz content

`data/` holds one JSON file per quiz, covering the full 9-week Data Engineering
curriculum end to end. `seed.py` loads all of them on startup, in the order
the material is taught:

| File | Quiz | Questions |
|---|---|---|
| `data_engineering_basics.json` | Data Engineering Basics | 13 |
| `python_for_data_engineering.json` | Python for Data Engineering | 13 |
| `data_storage_and_formats.json` | Data Storage and File Formats | 12 |
| `relational_databases_sql.json` | Relational Databases and SQL | 13 |
| `nosql_databases.json` | Non-Relational (NoSQL) Databases | 11 |
| `data_warehousing_and_architecture.json` | Data Warehousing and Data Architecture | 12 |
| `data_ingestion_methods.json` | Data Ingestion Methods | 10 |
| `apache_spark.json` | Apache Spark | 11 |
| `apache_kafka.json` | Apache Kafka | 10 |
| `apache_airflow.json` | Apache Airflow | 10 |
| `batch_and_stream_processing.json` | Batch and Stream Processing | 10 |
| `cloud_platforms.json` | Cloud Platforms for Data Engineering (AWS, GCP, Azure) | 12 |

Each file mirrors the same 8 topics covered hands-on in `labs/` (ETL, databases,
Spark, Kafka, Airflow, cloud, batch/stream), plus the Unix/shell and Python
fundamentals the labs assume. Field names (`question_text`, `option_a`–`option_d`,
`correct_answer`) match the admin "Add Questions" form, so questions can be
entered as-is through the admin panel or loaded with the seed script.

## Running the app

This is a Flask app with SQLite storage via SQLAlchemy, and login via Flask-Login.

```bash
python -m venv venv
source venv/bin/activate      # on Windows: venv\Scripts\activate

pip install -r requirements.txt

# creates quizeers.db, an admin user, a demo user, and loads the
# Data Engineering Basics quiz from data/data_engineering_basics.json
python seed.py

python run.py
```

Then open http://127.0.0.1:5000 in your browser.

**Seeded logins**
| Role  | Email                  | Password |
|-------|------------------------|----------|
| Admin | admin@quizeers.local   | admin123 |
| User  | user@quizeers.local    | user123  |

Log in as the admin to add/edit/delete quizzes and questions from `/admin`, or as the demo user to take quizzes from the home page and see your scores under "My Results".

To start over, stop the app and delete `quizeers.db`, then run `python seed.py` again.

## Project structure

The app follows a Flask application-factory + blueprints layout, so each
concern lives in its own file rather than one large `app.py`:

```
quizeers/                  # the Flask application package
  __init__.py               # create_app() -- the only place everything is wired together
  config.py                 # Config classes
  extensions.py             # db, login_manager instances (avoids circular imports)
  models.py                 # User, Quiz, Question, Answer, Result, QuestionAttempt
  decorators.py              # @admin_required
  lab_catalog.py              # static data describing labs/ for the Labs pages
  blueprints/
    auth.py                   # register, login, logout
    quizzes.py                 # home, take a quiz, view your own results, profile
    admin.py                    # quiz/question CRUD, all-results view, user management
    labs.py                      # labs overview + the live ETL demo
    analytics.py                  # the ETL-powered learning-analytics dashboard
  utils/
    quiz_helpers.py            # answer shuffling, quiz-settings-from-form parsing
    import_parsing.py           # bulk question import (JSON/CSV) parsing

run.py                      # entry point: python3 run.py
seed.py                     # loads demo users + all quizzes in data/
analytics_etl/              # standalone ETL pipeline (separate from the web app on purpose --
                             # see analytics_etl/pipeline.py's docstring)
labs/                       # the full hands-on curriculum labs (see labs/README.md)
templates/, static/         # Jinja templates and CSS
data/                       # quiz question banks, one JSON file per quiz
```

Each blueprint only imports what it needs (models, its own utils) and
never reaches into another blueprint's routes directly -- cross-blueprint
navigation goes through `url_for("blueprint_name.view_name")`, same as any
other Flask route reference.

## Features

**Taking a quiz**
- Questions and answer options are shuffled per attempt (toggle per-quiz in admin)
- Optional countdown timer with auto-submit when time runs out
- Live progress bar showing how many questions are answered
- Optional cap on attempts per quiz; home page shows your best score and attempts used

**Admin**
- Quiz categories, difficulty levels, time limits, and attempt limits (`/admin`)
- Bulk-import questions via pasted JSON or CSV (`/admin/quiz/<id>/questions/add` → "Bulk import")
- User management: promote/demote admins, reset a user's password, delete a user (`/admin/users`)
- Soft-delete/restore for quizzes

**Account**
- Profile page with quiz history and a change-password form (`/profile`)

**Quiz ↔ Lab linking**
- `quizeers/lab_catalog.py` maps each lab (and each week of the full
  syllabus) to the `Quiz.title`(s) it's the hands-on counterpart to — one
  lab can back several quizzes (`03_databases` → Relational DBs & SQL,
  NoSQL, and Data Warehousing all at once) and the mapping resolves
  against the real Quiz table on every request, so it never points at a
  deleted or renamed quiz.
- On `/labs`, every lab and every week card shows badges linking straight
  to its matching quiz/quizzes ("Practice this on: ...").
- On the home page, every quiz card that has a matching lab shows a
  "Hands-on lab" link back to `/labs#lab-<slug>`.
- A lab with no quiz yet says so ("No matching quiz yet") rather than
  guessing a link — currently that's just the Week 6 (governance) and
  Week 9 (demo/presentation) syllabus weeks, which aren't quizzed.
