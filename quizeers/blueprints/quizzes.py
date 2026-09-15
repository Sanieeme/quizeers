"""
The user-facing quiz experience: browsing quizzes, taking one, viewing
your own past results, and basic account/profile management. Nothing in
here touches admin CRUD, analytics, or the labs content.
"""
import random

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from quizeers.extensions import db
from quizeers.models import Quiz, Result, QuestionAttempt
from quizeers.utils.quiz_helpers import with_shuffled_answers

bp = Blueprint("quizzes", __name__)


@bp.route("/")
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


@bp.route("/quiz/<int:quiz_id>", methods=["GET", "POST"])
@login_required
def take_quiz(quiz_id):
    quiz = db.get_or_404(Quiz, quiz_id)
    attempts_used = Result.query.filter_by(user_id=current_user.id, quiz_id=quiz.id).count()

    if quiz.max_attempts and attempts_used >= quiz.max_attempts and request.method == "GET":
        flash(
            f"You've used all {quiz.max_attempts} attempt(s) for this quiz.",
            "error",
        )
        return redirect(url_for("quizzes.user_view_results"))

    if request.method == "POST":
        if quiz.max_attempts and attempts_used >= quiz.max_attempts:
            flash("No attempts remaining for this quiz.", "error")
            return redirect(url_for("quizzes.user_view_results"))

        questions = quiz.questions
        correct = 0
        attempt_rows = []
        for question in questions:
            submitted = request.form.get(f"question_{question.id}")
            correct_option = next(
                a for a in question.answers if a.letter == question.correct_answer
            )
            chosen_option = next((a for a in question.answers if a.text == submitted), None)
            is_correct = chosen_option is not None and chosen_option.letter == question.correct_answer
            if is_correct:
                correct += 1
            attempt_rows.append({
                "question_id": question.id,
                "chosen_answer": chosen_option.letter if chosen_option else None,
                "is_correct": is_correct,
            })

        score = round((correct / len(questions)) * 100) if questions else 0
        result = Result(user_id=current_user.id, quiz_id=quiz.id, score=score)
        db.session.add(result)
        db.session.flush()  # assigns result.id without a separate commit round-trip

        for row in attempt_rows:
            db.session.add(QuestionAttempt(
                result_id=result.id,
                user_id=current_user.id,
                quiz_id=quiz.id,
                question_id=row["question_id"],
                chosen_answer=row["chosen_answer"],
                is_correct=row["is_correct"],
            ))

        db.session.commit()
        flash(f"You scored {score}% on {quiz.title}.", "success")
        return redirect(url_for("quizzes.user_view_results"))

    # GET: build the (optionally shuffled) question/answer order for this attempt
    questions = list(quiz.questions)
    if quiz.shuffle_questions:
        random.shuffle(questions)
        questions = [with_shuffled_answers(q) for q in questions]

    return render_template(
        "take_quiz.html",
        quiz=quiz,
        questions=questions,
        attempts_used=attempts_used,
    )


@bp.route("/results")
@login_required
def user_view_results():
    results = (
        Result.query.filter_by(user_id=current_user.id)
        .order_by(Result.created_at.desc())
        .all()
    )
    return render_template("user_view_results.html", results=results)


@bp.route("/profile", methods=["GET", "POST"])
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
        return redirect(url_for("quizzes.profile"))

    attempt_count = Result.query.filter_by(user_id=current_user.id).count()
    return render_template("profile.html", attempt_count=attempt_count)
