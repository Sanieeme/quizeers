import csv
import io
import json
import os
import random
import secrets
from datetime import datetime, timezone
from types import SimpleNamespace

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "quizeers.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
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


DIFFICULTIES = ["Easy", "Medium", "Hard"]


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


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        is_admin = bool(request.form.get("is_admin"))

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return redirect(url_for("register"))

        user = User(email=email, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("admin_panel") if user.is_admin else url_for("home"))

        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Home / taking quizzes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    category = request.args.get("category", "").strip()
    query = Quiz.query.filter_by(is_deleted=False)
    if category:
        query = query.filter_by(category=category)
    quizzes = query.all()

    categories = sorted({
        q.category for q in Quiz.query.filter_by(is_deleted=False).all() if q.category
    })

    attempt_counts = {}
    best_scores = {}
    if current_user.is_authenticated:
        for quiz in quizzes:
            results = Result.query.filter_by(user_id=current_user.id, quiz_id=quiz.id).all()
            attempt_counts[quiz.id] = len(results)
            best_scores[quiz.id] = max((r.score for r in results), default=None)

    return render_template(
        "home.html",
        quizzes=quizzes,
        categories=categories,
        selected_category=category,
        attempt_counts=attempt_counts,
        best_scores=best_scores,
    )


@app.route("/quiz/<int:quiz_id>", methods=["GET", "POST"])
@login_required
def take_quiz(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)
    attempts_used = Result.query.filter_by(user_id=current_user.id, quiz_id=quiz.id).count()

    if quiz.max_attempts and attempts_used >= quiz.max_attempts and request.method == "GET":
        flash(
            f"You've used all {quiz.max_attempts} attempt(s) for this quiz.",
            "error",
        )
        return redirect(url_for("user_view_results"))

    if request.method == "POST":
        if quiz.max_attempts and attempts_used >= quiz.max_attempts:
            flash("No attempts remaining for this quiz.", "error")
            return redirect(url_for("user_view_results"))

        questions = quiz.questions
        correct = 0
        for question in questions:
            submitted = request.form.get(f"question_{question.id}")
            correct_option = next(
                a for a in question.answers if a.letter == question.correct_answer
            )
            if submitted == correct_option.text:
                correct += 1

        score = round((correct / len(questions)) * 100) if questions else 0
        result = Result(user_id=current_user.id, quiz_id=quiz.id, score=score)
        db.session.add(result)
        db.session.commit()
        flash(f"You scored {score}% on {quiz.title}.", "success")
        return redirect(url_for("user_view_results"))

    # GET: build the (optionally shuffled) question/answer order for this attempt
    questions = list(quiz.questions)
    if quiz.shuffle_questions:
        random.shuffle(questions)
        questions = [_with_shuffled_answers(q) for q in questions]

    return render_template(
        "take_quiz.html",
        quiz=quiz,
        questions=questions,
        attempts_used=attempts_used,
    )


def _with_shuffled_answers(question):
    """Return a lightweight view of `question` with its answers in random order.

    Grading is unaffected: the submitted radio value is still the option TEXT,
    and take_quiz() looks up the correct answer by letter, not by position.
    """
    shuffled = random.sample(question.answers, k=len(question.answers))
    return SimpleNamespace(id=question.id, text=question.text, answers=shuffled)


@app.route("/results")
@login_required
def user_view_results():
    results = (
        Result.query.filter_by(user_id=current_user.id)
        .order_by(Result.created_at.desc())
        .all()
    )
    return render_template("user_view_results.html", results=results)


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if not current_user.check_password(current_password):
            flash("Current password is incorrect.", "error")
        elif len(new_password) < 6:
            flash("New password must be at least 6 characters.", "error")
        elif new_password != confirm_password:
            flash("New password and confirmation do not match.", "error")
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash("Password updated.", "success")
        return redirect(url_for("profile"))

    attempt_count = Result.query.filter_by(user_id=current_user.id).count()
    return render_template("profile.html", attempt_count=attempt_count)


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin_panel():
    quizzes = Quiz.query.filter_by(is_deleted=False).all()
    return render_template("admin_panel.html", quizzes=quizzes)


@app.route("/admin/quiz/add", methods=["GET", "POST"])
@admin_required
def admin_add_quiz():
    if request.method == "POST":
        quiz = Quiz(
            title=request.form["title"].strip(),
            description=request.form.get("description", "").strip(),
            **_quiz_settings_from_form(request.form),
        )
        db.session.add(quiz)
        db.session.commit()
        flash("Quiz added.", "success")
        return redirect(url_for("admin_add_questions", quiz_id=quiz.id))

    return render_template("admin_add_quiz.html", difficulties=DIFFICULTIES)


def _quiz_settings_from_form(form):
    def _int_or_none(field):
        raw = form.get(field, "").strip()
        return int(raw) if raw else None

    return {
        "category": form.get("category", "").strip() or "General",
        "difficulty": form.get("difficulty", "Medium").strip() or "Medium",
        "time_limit_minutes": _int_or_none("time_limit_minutes"),
        "max_attempts": _int_or_none("max_attempts"),
        "shuffle_questions": bool(form.get("shuffle_questions")),
    }


@app.route("/admin/quiz/<int:quiz_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_quiz(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)

    if request.method == "POST":
        quiz.title = request.form["title"].strip()
        quiz.description = request.form.get("description", "").strip()
        for key, value in _quiz_settings_from_form(request.form).items():
            setattr(quiz, key, value)
        db.session.commit()
        flash("Quiz updated.", "success")
        return redirect(url_for("admin_panel"))

    return render_template("admin_edit_quiz.html", quiz=quiz, difficulties=DIFFICULTIES)


@app.route("/admin/quiz/<int:quiz_id>/delete")
@admin_required
def admin_delete_quiz(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)
    quiz.is_deleted = True
    db.session.commit()
    flash("Quiz deleted.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/quizzes/deleted")
@admin_required
def admin_deleted_quizzes():
    quizzes = Quiz.query.filter_by(is_deleted=True).all()
    return render_template("admin_deleted_quizzes.html", quizzes=quizzes)


@app.route("/admin/quiz/<int:quiz_id>/restore", methods=["POST"])
@admin_required
def admin_restore_quiz(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)
    quiz.is_deleted = False
    db.session.commit()
    flash("Quiz restored.", "success")
    return redirect(url_for("admin_deleted_quizzes"))


@app.route("/admin/quiz/<int:quiz_id>/questions/add", methods=["GET", "POST"])
@admin_required
def admin_add_questions(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)

    if request.method == "POST":
        question = Question(
            quiz_id=quiz.id,
            text=request.form["question_text"].strip(),
            correct_answer=_letter_for_correct_answer(request.form),
        )
        db.session.add(question)
        db.session.flush()  # assigns question.id

        for letter, field in zip("ABCD", ["option_a", "option_b", "option_c", "option_d"]):
            db.session.add(Answer(
                question_id=question.id,
                text=request.form[field].strip(),
                letter=letter,
            ))

        db.session.commit()
        flash("Question added.", "success")
        return redirect(url_for("admin_add_questions", quiz_id=quiz.id))

    return render_template("admin_add_questions.html", quiz=quiz)


def _letter_for_correct_answer(form):
    """Accept either a letter (A-D) or the option's exact text in correct_answer."""
    raw = form["correct_answer"].strip()
    if raw.upper() in ("A", "B", "C", "D"):
        return raw.upper()

    for letter, field in zip("ABCD", ["option_a", "option_b", "option_c", "option_d"]):
        if form[field].strip() == raw:
            return letter

    raise ValueError("correct_answer must match one of the options, or be A/B/C/D")


@app.route("/admin/quiz/<int:quiz_id>/questions/import", methods=["GET", "POST"])
@admin_required
def admin_import_questions(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)

    if request.method == "POST":
        fmt = request.form.get("format", "json")
        raw = request.form.get("payload", "")

        try:
            rows = _parse_import_payload(raw, fmt)
        except Exception as exc:
            flash(f"Could not parse {fmt.upper()} input: {exc}", "error")
            return redirect(url_for("admin_import_questions", quiz_id=quiz.id))

        added = 0
        errors = []
        for i, row in enumerate(rows, start=1):
            try:
                letter = _letter_for_correct_answer(row)
            except (KeyError, ValueError) as exc:
                errors.append(f"Row {i}: {exc}")
                continue

            question = Question(quiz_id=quiz.id, text=row["question_text"].strip(), correct_answer=letter)
            db.session.add(question)
            db.session.flush()
            for letter_code, field in zip("ABCD", ["option_a", "option_b", "option_c", "option_d"]):
                db.session.add(Answer(question_id=question.id, text=row[field].strip(), letter=letter_code))
            added += 1

        db.session.commit()
        if added:
            flash(f"Imported {added} question(s).", "success")
        if errors:
            flash("Some rows were skipped: " + "; ".join(errors), "error")
        return redirect(url_for("admin_add_questions", quiz_id=quiz.id))

    return render_template("admin_import_questions.html", quiz=quiz)


def _parse_import_payload(raw, fmt):
    if fmt == "csv":
        reader = csv.DictReader(io.StringIO(raw))
        rows = list(reader)
        required = {"question_text", "option_a", "option_b", "option_c", "option_d", "correct_answer"}
        for row in rows:
            missing = required - row.keys()
            if missing:
                raise ValueError(f"missing column(s): {', '.join(sorted(missing))}")
        return rows

    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of question objects")
    return data


@app.route("/admin/question/<int:question_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_question(question_id):
    question = db.get_or_404(Question, question_id)
    answers = question.answers  # ordered A, B, C, D

    if request.method == "POST":
        question.text = request.form["question_text"].strip()
        question.correct_answer = request.form["correct_answer"].strip().upper()

        for answer, field in zip(answers, ["option_a", "option_b", "option_c", "option_d"]):
            answer.text = request.form[field].strip()

        db.session.commit()
        flash("Question updated.", "success")
        return redirect(url_for("admin_add_questions", quiz_id=question.quiz_id))

    return render_template("admin_edit_question.html", question=question, answers=answers)


@app.route("/admin/question/<int:question_id>/delete")
@admin_required
def admin_delete_question(question_id):
    question = db.get_or_404(Question, question_id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash("Question deleted.", "success")
    return redirect(url_for("admin_add_questions", quiz_id=quiz_id))


@app.route("/admin/results")
@admin_required
def admin_view_results():
    results = Result.query.order_by(Result.created_at.desc()).all()
    return render_template("admin_view_results.html", results=results)


# ---------------------------------------------------------------------------
# Admin: user management
# ---------------------------------------------------------------------------
@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.order_by(User.email).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/toggle_admin", methods=["POST"])
@admin_required
def admin_toggle_admin(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You can't change your own admin status.", "error")
        return redirect(url_for("admin_users"))

    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"{user.email} is now {'an admin' if user.is_admin else 'a regular user'}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    user = db.get_or_404(User, user_id)
    temp_password = secrets.token_urlsafe(9)
    user.set_password(temp_password)
    db.session.commit()
    flash(f"Password for {user.email} reset to: {temp_password} (share this with them securely)", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You can't delete your own account.", "error")
        return redirect(url_for("admin_users"))

    Result.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f"Deleted user {user.email}.", "success")
    return redirect(url_for("admin_users"))


# ---------------------------------------------------------------------------
# CLI helper: `flask --app app.py init-db`
# ---------------------------------------------------------------------------
@app.cli.command("init-db")
def init_db():
    """Create all tables."""
    db.create_all()
    print("Database tables created.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
