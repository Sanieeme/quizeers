"""
Admin Routes
"""


from fastapi import APIRouter



router = APIRouter()







@router.get("/users")
def get_users():


    return {


        "users":[

            {

            "id":1,

            "email":
            "student@gmail.com",

            "role":
            "student"

            }


        ]

    }








@router.delete(
"/users/{user_id}"
)
def delete_user(
    user_id:int
):


    return {


        "message":
        f"User {user_id} deleted"

    }








@router.delete(
"/quizzes/{quiz_id}"
)
def delete_quiz(
    quiz_id:int
):


    return {


        "message":
        f"Quiz {quiz_id} deleted"

    }