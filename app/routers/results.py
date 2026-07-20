"""
Results Routes
"""


from fastapi import APIRouter


from app.schemas.result_schema import (
    ResultCreate
)



router = APIRouter()







@router.post("/submit")
def submit_result(
    result:ResultCreate
):


    return {


        "message":
        "Quiz submitted",


        "score":
        85


    }







@router.get("/")
def get_results():


    return [

        {

        "quiz":
        "Python Basics",

        "score":
        90

        }

    ]