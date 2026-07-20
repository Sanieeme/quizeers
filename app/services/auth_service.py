"""
Authentication Business Logic

Handles:
- User registration
- Login validation
- Password security
"""


from passlib.context import CryptContext



pwd_context = CryptContext(

    schemes=["bcrypt"],

    deprecated="auto"

)





# ============================
# PASSWORD HASHING
# ============================


def hash_password(password:str):


    return pwd_context.hash(
        password
    )







def verify_password(
        plain_password,
        hashed_password
):


    return pwd_context.verify(

        plain_password,

        hashed_password

    )









# ============================
# CREATE USER
# ============================


def create_user(
    db,
    user_data
):


    hashed = hash_password(
        user_data.password
    )



    user = {


        "username":
        user_data.username,


        "email":
        user_data.email,


        "password_hash":
        hashed,


        "role":
        "student"


    }


    # Later:
    # db.add(user)


    return user







# ============================
# LOGIN
# ============================


def authenticate_user(
    email,
    password
):


    """
    Verify user credentials
    """


    # Later:
    # Find user from database


    user = {


        "email":
        email,


        "role":
        "student"


    }



    return user