"""
Database models. This module has exactly one job: define the schema.
No routes, no request handling, no business logic beyond what belongs on
the model itself (password hashing lives here because it's a property of
a User, not because it's convenient).
"""
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from quizeers.extensions import db

DIFFICULTIES = ["Easy", "Medium", "Hard"]


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, default="")
    is_deleted = db.Column(db.Boolean, default=False)
    category = db.Column(db.String(100), default="General")
    difficulty = db.Column(db.String(20), default="Medium")
    # Optional time limit for taking the quiz; null/0 = untimed
    time_limit_minutes = db.Column(db.Integer, nullable=True)
    # Optional cap on how many times a user may attempt the quiz; null = unlimited
    max_attempts = db.Column(db.Integer, nullable=True)
    shuffle_questions = db.Column(db.Boolean, default=True)

    questions = db.relationship(
        "Question", backref="quiz", lazy=True, cascade="all, delete-orphan"
    )


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    # Letter of the correct option: 'A', 'B', 'C', or 'D'
    correct_answer = db.Column(db.String(1), nullable=False)

    answers = db.relationship(
        "Answer", backref="question", lazy=True, cascade="all, delete-orphan",
        order_by="Answer.letter"
    )


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    text = db.Column(db.String(500), nullable=False)
    letter = db.Column(db.String(1), nullable=False)  # 'A', 'B', 'C', 'D'


class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)
    score = db.Column(db.Integer, nullable=False)  # percentage, 0-100
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User")
    quiz = db.relationship("Quiz")


class QuestionAttempt(db.Model):
    """One row per question answered in a quiz attempt.

    This is the raw operational event data the analytics ETL pipeline
    (analytics_etl/) extracts from: without per-question records, there's
    nothing more granular than a final percentage to build a warehouse from.
    """
    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey("result.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    chosen_answer = db.Column(db.String(1), nullable=True)  # letter, or NULL if left blank
    is_correct = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    result = db.relationship("Result", backref="question_attempts")
    question = db.relationship("Question")
