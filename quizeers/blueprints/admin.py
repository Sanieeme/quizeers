"""
Admin-only management: quizzes, questions, viewing all results, and user
management. Everything here is gated by @admin_required. Deliberately
does not contain analytics or labs routes -- those are separate concerns
with their own blueprints, even though they're also admin-only.
"""
import secrets

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import current_user

from quizeers.extensions import db
from quizeers.decorators import admin_required
from quizeers.models import Quiz, Question, Answer, Result, User, DIFFICULTIES
from quizeers.utils.quiz_helpers import quiz_settings_from_form
from quizeers.utils.import_parsing import letter_for_correct_answer, parse_import_payload

bp = Blueprint("admin", __name__, url_prefix="/admin")


# ---------------------------------------------------------------------------
# Quizzes
# ---------------------------------------------------------------------------
@bp.route("")
@admin_required
def admin_panel():
    quizzes = Quiz.query.filter_by(is_deleted=False).all()
    return render_template("admin_panel.html", quizzes=quizzes)


@bp.route("/quiz/add", methods=["GET", "POST"])
@admin_required
def admin_add_quiz():
    if request.method == "POST":
        quiz = Quiz(
            title=request.form["title"].strip(),
            description=request.form.get("description", "").strip(),
            **quiz_settings_from_form(request.form),
        )
        db.session.add(quiz)
        db.session.commit()
        flash("Quiz added.", "success")
        return redirect(url_for("admin.admin_add_questions", quiz_id=quiz.id))

    return render_template("admin_add_quiz.html", difficulties=DIFFICULTIES)


@bp.route("/quiz/<int:quiz_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_quiz(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)

    if request.method == "POST":
        quiz.title = request.form["title"].strip()
        quiz.description = request.form.get("description", "").strip()
        for key, value in quiz_settings_from_form(request.form).items():
            setattr(quiz, key, value)
        db.session.commit()
        flash("Quiz updated.", "success")
        return redirect(url_for("admin.admin_panel"))

    return render_template("admin_edit_quiz.html", quiz=quiz, difficulties=DIFFICULTIES)


@bp.route("/quiz/<int:quiz_id>/delete")
@admin_required
def admin_delete_quiz(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)
    quiz.is_deleted = True
    db.session.commit()
    flash("Quiz deleted.", "success")
    return redirect(url_for("admin.admin_panel"))


@bp.route("/quizzes/deleted")
@admin_required
def admin_deleted_quizzes():
    quizzes = Quiz.query.filter_by(is_deleted=True).all()
    return render_template("admin_deleted_quizzes.html", quizzes=quizzes)


@bp.route("/quiz/<int:quiz_id>/restore", methods=["POST"])
@admin_required
def admin_restore_quiz(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)
    quiz.is_deleted = False
    db.session.commit()
    flash("Quiz restored.", "success")
    return redirect(url_for("admin.admin_deleted_quizzes"))


# ---------------------------------------------------------------------------
# Questions
# ---------------------------------------------------------------------------
@bp.route("/quiz/<int:quiz_id>/questions/add", methods=["GET", "POST"])
@admin_required
def admin_add_questions(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)

    if request.method == "POST":
        question = Question(
            quiz_id=quiz.id,
            text=request.form["question_text"].strip(),
            correct_answer=letter_for_correct_answer(request.form),
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
        return redirect(url_for("admin.admin_add_questions", quiz_id=quiz.id))

    return render_template("admin_add_questions.html", quiz=quiz)


@bp.route("/quiz/<int:quiz_id>/questions/import", methods=["GET", "POST"])
@admin_required
def admin_import_questions(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)

    if request.method == "POST":
        fmt = request.form.get("format", "json")
        raw = request.form.get("payload", "")

        try:
            rows = parse_import_payload(raw, fmt)
        except Exception as exc:
            flash(f"Could not parse {fmt.upper()} input: {exc}", "error")
            return redirect(url_for("admin.admin_import_questions", quiz_id=quiz.id))

        added = 0
        errors = []
        for i, row in enumerate(rows, start=1):
            try:
                letter = letter_for_correct_answer(row)
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
        return redirect(url_for("admin.admin_add_questions", quiz_id=quiz.id))

    return render_template("admin_import_questions.html", quiz=quiz)


@bp.route("/question/<int:question_id>/edit", methods=["GET", "POST"])
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
        return redirect(url_for("admin.admin_add_questions", quiz_id=question.quiz_id))

    return render_template("admin_edit_question.html", question=question, answers=answers)


@bp.route("/question/<int:question_id>/delete")
@admin_required
def admin_delete_question(question_id):
    question = db.get_or_404(Question, question_id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash("Question deleted.", "success")
    return redirect(url_for("admin.admin_add_questions", quiz_id=quiz_id))


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
@bp.route("/results")
@admin_required
def admin_view_results():
    results = Result.query.order_by(Result.created_at.desc()).all()
    return render_template("admin_view_results.html", results=results)


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------
@bp.route("/users")
@admin_required
def admin_users():
    users = User.query.order_by(User.email).all()
    return render_template("admin_users.html", users=users)


@bp.route("/users/<int:user_id>/toggle_admin", methods=["POST"])
@admin_required
def admin_toggle_admin(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You can't change your own admin status.", "error")
        return redirect(url_for("admin.admin_users"))

    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"{user.email} is now {'an admin' if user.is_admin else 'a regular user'}.", "success")
    return redirect(url_for("admin.admin_users"))


@bp.route("/users/<int:user_id>/reset_password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    user = db.get_or_404(User, user_id)
    temp_password = secrets.token_urlsafe(9)
    user.set_password(temp_password)
    db.session.commit()
    flash(f"Password for {user.email} reset to: {temp_password} (share this with them securely)", "success")
    return redirect(url_for("admin.admin_users"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You can't delete your own account.", "error")
        return redirect(url_for("admin.admin_users"))

    Result.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f"Deleted user {user.email}.", "success")
    return redirect(url_for("admin.admin_users"))
