"""
ETL Load Stage

Stores processed analytics.
"""


from sqlalchemy import text


from app.database.connection import engine









def save_dataframe(

    dataframe,

    table_name

):


    dataframe.to_sql(

        table_name,

        engine,

        if_exists="replace",

        index=False

    )











def load_analytics(

    transformed_data

):


    save_dataframe(

        transformed_data["user_performance"],

        "analytics_users"

    )



    save_dataframe(

        transformed_data["quiz_statistics"],

        "analytics_quizzes"

    )



    return {


        "status":

        "Analytics loaded successfully"

    }