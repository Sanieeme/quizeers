"""
QuizVerse Analytics Pipeline


Runs complete ETL process:

Extract
Transform
Load


This can later be scheduled with:

- Apache Airflow
- Prefect
- Cron Jobs
- GitHub Actions

"""



from data_engineering.etl.extract import extract_all
from data_engineering.etl.transform import transform_data
from data_engineering.etl.load import load_analytics


from data_engineering.etl.transform import (

    transform_data

)



from data_engineering.etl.load import (

    load_analytics

)







# ============================
# PIPELINE EXECUTION
# ============================



def run_quiz_pipeline():


    print(

        "Starting QuizVerse ETL Pipeline..."

    )



    # ----------------------------
    # STEP 1: EXTRACT
    # ----------------------------


    print(

        "Extracting database data..."

    )



    raw_data = extract_all()





    print(

        "Extraction completed"

    )







    # ----------------------------
    # STEP 2: TRANSFORM
    # ----------------------------



    print(

        "Transforming data..."

    )



    analytics_data = transform_data(

        raw_data

    )





    print(

        "Transformation completed"

    )








    # ----------------------------
    # STEP 3: LOAD
    # ----------------------------



    print(

        "Loading analytics tables..."

    )



    result = load_analytics(

        analytics_data

    )





    print(

        result["status"]

    )





    print(

        "Pipeline completed successfully"

    )








# ============================
# RUN PIPELINE DIRECTLY
# ============================



if __name__ == "__main__":


    run_quiz_pipeline()