"""
User Routes
"""


from fastapi import APIRouter


from app.schemas.user_schema import (
    UserResponse,
    UserUpdate
)



router = APIRouter()







@router.get(
    "/profile",
    response_model=UserResponse
)
def get_profile():



    return {


        "id":1,


        "username":
        "Sarah",


        "email":
        "sarah@email.com",


        "role":
        "student",


        "is_active":
        True


    }








@router.put("/profile")
def update_profile(
    user:UserUpdate
):


    return {


        "message":
        "Profile updated",


        "data":
        user

    }