"""
ETL Extract Stage

Responsible for extracting
raw data from database.

Tools:

- SQLAlchemy
- Pandas

"""


import pandas as pd


from sqlalchemy import text


from app.database.connection import engine







# ============================
# EXTRACT USERS
# ============================


def extract_users():


    query = """

    SELECT

        id,

        username,

        email,

        role,

        created_at


    FROM users

    """



    df = pd.read_sql(

        text(query),

        engine

    )



    return df









# ============================
# EXTRACT QUIZZES
# ============================


def extract_quizzes():


    query = """

    SELECT

        id,

        title,

        category,

        difficulty,

        created_at


    FROM quizzes

    """



    df = pd.read_sql(

        text(query),

        engine

    )


    return df









# ============================
# EXTRACT RESULTS
# ============================


def extract_results():


    query = """

    SELECT


        id,

        user_id,

        quiz_id,

        score,

        completed_at



    FROM results


    """



    df = pd.read_sql(

        text(query),

        engine

    )


    return df









# ============================
# EXTRACT EVERYTHING
# ============================


def extract_all():


    return {


        "users":

        extract_users(),



        "quizzes":

        extract_quizzes(),



        "results":

        extract_results()


    }