"""
Seed the database with:
  - an admin user (admin@quizeers.local / admin123)
  - a demo user  (user@quizeers.local  / user123)
  - every quiz found as a JSON file in data/ (the full 9-week Data
    Engineering programme: ETL, Unix/Linux, Python, data storage,
    relational & non-relational databases, data warehousing and
    architecture, ingestion methods, Spark, Kafka, Airflow, batch/stream
    processing, and AWS/GCP/Azure cloud platforms)

Run with:  python seed.py
"""
import glob
import json
import os

from quizeers import create_app
from quizeers.extensions import db
from quizeers.models import User, Quiz, Question, Answer

app = create_app()

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# Loaded first, then remaining files in alphabetical order, so the
# programme reads roughly in the order it's taught.
PREFERRED_ORDER = [
    "data_engineering_basics.json",
    "python_for_data_engineering.json",
    "data_storage_and_formats.json",
    "relational_databases_sql.json",
    "nosql_databases.json",
    "data_warehousing_and_architecture.json",
    "data_ingestion_methods.json",
    "apache_spark.json",
    "apache_kafka.json",
    "apache_airflow.json",
    "batch_and_stream_processing.json",
    "cloud_platforms.json",
]


def discover_data_files():
    all_files = {os.path.basename(p) for p in glob.glob(os.path.join(DATA_DIR, "*.json"))}
    ordered = [f for f in PREFERRED_ORDER if f in all_files]
    remaining = sorted(all_files - set(ordered))
    return [os.path.join(DATA_DIR, f) for f in ordered + remaining]


def get_or_create_user(email, password, is_admin):
    user = User.query.filter_by(email=email).first()
    if user:
        return user
    user = User(email=email, is_admin=is_admin)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    return user


def seed_quiz_from_json(path):
    with open(path) as f:
        data = json.load(f)

    quiz_data = data["quiz"]
    quiz = Quiz.query.filter_by(title=quiz_data["title"]).first()
    if quiz:
        print(f"Quiz '{quiz.title}' already exists, skipping.")
        return

    quiz = Quiz(
        title=quiz_data["title"],
        description=quiz_data.get("description", ""),
        category=quiz_data.get("category", "Data Engineering"),
        difficulty=quiz_data.get("difficulty", "Medium"),
        time_limit_minutes=quiz_data.get("time_limit_minutes", 15),
        max_attempts=quiz_data.get("max_attempts", 3),
        shuffle_questions=True,
    )
    db.session.add(quiz)
    db.session.flush()  # get quiz.id

    for q in data["questions"]:
        options = {
            "A": q["option_a"],
            "B": q["option_b"],
            "C": q["option_c"],
            "D": q["option_d"],
        }
        correct_letter = next(
            letter for letter, text in options.items() if text == q["correct_answer"]
        )

        question = Question(
            quiz_id=quiz.id,
            text=q["question_text"],
            correct_answer=correct_letter,
        )
        db.session.add(question)
        db.session.flush()

        for letter, text in options.items():
            db.session.add(Answer(question_id=question.id, text=text, letter=letter))

    print(f"Loaded quiz '{quiz.title}' with {len(data['questions'])} questions.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        get_or_create_user("admin@quizeers.local", "admin123", is_admin=True)
        get_or_create_user("user@quizeers.local", "user123", is_admin=False)
        for data_file in discover_data_files():
            seed_quiz_from_json(data_file)
        db.session.commit()
        print("Done. Admin login: admin@quizeers.local / admin123")
        print("      Demo login:  user@quizeers.local / user123")
