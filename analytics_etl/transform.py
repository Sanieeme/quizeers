"""
Transform step: turn raw, row-level operational data into the aggregates a
reporting dashboard actually wants.

This is the part of the pipeline that has real substance: the operational
schema is optimized for serving a quiz one question at a time, not for
answering "which questions trip people up" or "is this cohort improving
over time" -- those need joins and aggregation across attempts, and doing
that on every dashboard page load against the live app database would be
wasteful and would compete with real user traffic. Computing it once here
and loading the result into a separate warehouse (load.py) is the point.
"""
import pandas as pd


def transform(raw: dict) -> dict:
    attempts = raw["attempts"].copy()
    qa = raw["question_attempts"].copy()
    questions = raw["questions"].copy()
    quizzes = raw["quizzes"].copy()
    users = raw["users"].copy()

    if attempts.empty:
        print("[transform] no attempts yet -- nothing to aggregate")
        return {
            "quiz_performance": pd.DataFrame(),
            "question_difficulty": pd.DataFrame(),
            "category_performance": pd.DataFrame(),
            "score_trend": pd.DataFrame(),
            "user_progress": pd.DataFrame(),
        }

    attempts["created_at"] = pd.to_datetime(attempts["created_at"])
    attempts = attempts.merge(quizzes, left_on="quiz_id", right_on="id", suffixes=("", "_quiz"))

    # 1. Per-quiz performance: average score and attempt count
    quiz_performance = (
        attempts.groupby(["quiz_id", "title"])
        .agg(avg_score=("score", "mean"), attempts=("score", "count"))
        .reset_index()
        .round({"avg_score": 1})
        .sort_values("avg_score")
    )

    # 2. Per-question difficulty: % of attempts answered correctly.
    # Low percent-correct = a question most people get wrong -- exactly the
    # kind of signal that's invisible from the 'score per attempt' view.
    if not qa.empty:
        qa_with_quiz = qa.merge(questions[["id", "text"]], left_on="question_id", right_on="id",
                                 suffixes=("", "_q"))
        question_difficulty = (
            qa_with_quiz.groupby(["question_id", "text"])
            .agg(times_answered=("is_correct", "count"), pct_correct=("is_correct", "mean"))
            .reset_index()
        )
        question_difficulty["pct_correct"] = (question_difficulty["pct_correct"] * 100).round(1)
        question_difficulty = question_difficulty.sort_values("pct_correct")
    else:
        question_difficulty = pd.DataFrame()

    # 3. Per-category performance: rolls quizzes up to their category
    category_performance = (
        attempts.groupby("category")
        .agg(avg_score=("score", "mean"), attempts=("score", "count"))
        .reset_index()
        .round({"avg_score": 1})
        .sort_values("avg_score")
    )

    # 4. Score trend over time: average score per day, across all quizzes.
    # This is the kind of "is engagement/performance improving" view that
    # only makes sense once you aggregate across many individual attempts.
    attempts["date"] = attempts["created_at"].dt.date.astype(str)
    score_trend = (
        attempts.groupby("date")
        .agg(avg_score=("score", "mean"), attempts=("score", "count"))
        .reset_index()
        .round({"avg_score": 1})
        .sort_values("date")
    )

    # 5. Per-user progress: best score and number of quizzes attempted
    user_progress = (
        attempts.merge(users, left_on="user_id", right_on="id", suffixes=("", "_user"))
        .groupby(["user_id", "email"])
        .agg(quizzes_attempted=("quiz_id", "nunique"), best_score=("score", "max"), avg_score=("score", "mean"))
        .reset_index()
        .round({"avg_score": 1})
        .sort_values("avg_score", ascending=False)
    )

    print(f"[transform] quiz_performance: {len(quiz_performance)} rows")
    print(f"[transform] question_difficulty: {len(question_difficulty)} rows")
    print(f"[transform] category_performance: {len(category_performance)} rows")
    print(f"[transform] score_trend: {len(score_trend)} rows")
    print(f"[transform] user_progress: {len(user_progress)} rows")

    return {
        "quiz_performance": quiz_performance,
        "question_difficulty": question_difficulty,
        "category_performance": category_performance,
        "score_trend": score_trend,
        "user_progress": user_progress,
    }
