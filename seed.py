"""
Seed the database with:
  - an admin user (admin@quizeers.local / admin123)
  - a demo user  (user@quizeers.local  / user123)
  - the "Data Engineering Basics" quiz from data/data_engineering_basics.json

Run with:  python seed.py
"""
import json
import os

from app import app, db, User, Quiz, Question, Answer

DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "data_engineering_basics.json")


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
        category="Data Engineering",
        difficulty="Medium",
        time_limit_minutes=15,
        max_attempts=3,
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
        seed_quiz_from_json(DATA_FILE)
        db.session.commit()
        print("Done. Admin login: admin@quizeers.local / admin123")
        print("      Demo login:  user@quizeers.local / user123")
