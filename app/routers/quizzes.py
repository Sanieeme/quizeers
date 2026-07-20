"""
Quiz Routes
"""


from fastapi import APIRouter


from app.schemas.quiz_schema import (
    QuizCreate
)



router = APIRouter()







@router.get("/")
def get_quizzes():


    return [

        {


        "id":1,

        "title":
        "Python Basics",

        "category":
        "Programming",

        "difficulty":
        "Easy"


        }

    ]








@router.get("/{quiz_id}")
def get_quiz(
    quiz_id:int
):


    return {


        "id":quiz_id,


        "title":
        "Python Basics",


        "questions":[]


    }









@router.post("/")
def create_quiz(
    quiz:QuizCreate
):


    return {


        "message":
        "Quiz created",


        "quiz":
        quiz

    }