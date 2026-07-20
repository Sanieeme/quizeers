"""
ETL Transform Stage

Cleans data and creates analytics.
"""


import pandas as pd








# ============================
# USER PERFORMANCE
# ============================


def calculate_user_performance(results_df):


    # Convert score to numbers
    results_df["score"] = pd.to_numeric(
        results_df["score"],
        errors="coerce"
    )


    # Remove invalid scores
    results_df = results_df.dropna(
        subset=["score"]
    )


    performance = (

        results_df

        .groupby("user_id")

        .agg(

            total_quizzes=(

                "quiz_id",

                "count"

            ),


            average_score=(

                "score",

                "mean"

            )

        )

        .reset_index()

    )


    performance["average_score"] = (

        performance["average_score"]

        .round(2)

    )


    return performance






# ============================
# QUIZ ANALYTICS
# ============================


def calculate_quiz_statistics(results_df):


    results_df["score"] = pd.to_numeric(

        results_df["score"],

        errors="coerce"

    )


    results_df = results_df.dropna(

        subset=["score"]

    )


    stats = (

        results_df

        .groupby("quiz_id")

        .agg(

            attempts=(

                "id",

                "count"

            ),


            average_score=(

                "score",

                "mean"

            )

        )

        .reset_index()

    )


    stats["average_score"] = (

        stats["average_score"]

        .round(2)

    )


    return stats


# ============================
# COMPLETE TRANSFORMATION
# ============================


def transform_data(data):


    results = data["results"]



    return {


        "user_performance":

        calculate_user_performance(

            results

        ),



        "quiz_statistics":

        calculate_quiz_statistics(

            results

        )


    }