"""
Small, pure helper functions used by the quiz-taking and admin quiz-editing
routes. Pulled out of the route functions themselves so they're testable
in isolation and so blueprints/quizzes.py and blueprints/admin.py can both
use them without duplicating logic.
"""
import random
from types import SimpleNamespace


def with_shuffled_answers(question):
    """Return a lightweight view of `question` with its answers in random order.

    Grading is unaffected: the submitted radio value is still the option TEXT,
    and take_quiz() looks up the correct answer by letter, not by position.
    """
    shuffled = random.sample(question.answers, k=len(question.answers))
    return SimpleNamespace(id=question.id, text=question.text, answers=shuffled)


def quiz_settings_from_form(form):
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
