"""
Password Hashing

Handles:
- Password encryption
- Password verification
"""


from passlib.context import CryptContext






# BCrypt hashing algorithm


password_context = CryptContext(

    schemes=["bcrypt"],

    deprecated="auto"

)







def hash_password(
    password:str
):

    """
    Convert plain password
    into secure hash
    """


    return password_context.hash(
        password
    )









def verify_password(

    plain_password:str,

    hashed_password:str

):

    """
    Compare user password
    with stored hash
    """



    return password_context.verify(

        plain_password,

        hashed_password

    )