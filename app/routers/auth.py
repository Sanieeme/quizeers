"""
Authentication Routes

/register
/login
"""


from fastapi import APIRouter, HTTPException


from app.schemas.user_schema import (
    UserCreate,
    UserLogin,
    UserResponse
)



router = APIRouter()





@router.post(
    "/register",
    response_model=UserResponse
)
def register_user(
    user: UserCreate
):


    """
    Register new user
    """



    # Later:
    # save user to database


    return {


        "id":1,

        "username":user.username,

        "email":user.email,

        "role":"student",

        "is_active":True

    }









@router.post("/login")
def login_user(
    user:UserLogin
):


    """
    Login user
    """



    # Later:
    # verify password
    # generate JWT token



    return {


        "access_token":
        "sample-token",


        "token_type":
        "bearer"


    }