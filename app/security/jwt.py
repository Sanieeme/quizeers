"""
JWT Authentication

Handles:
- Token creation
- Token validation
"""


from datetime import datetime, timedelta


from jose import jwt, JWTError



from fastapi import HTTPException, status



from app.config import settings







# ============================
# CREATE TOKEN
# ============================



def create_access_token(

    data:dict

):


    payload = data.copy()



    expire = (

        datetime.utcnow()

        +

        timedelta(

            minutes=

            settings.ACCESS_TOKEN_EXPIRE_MINUTES

        )

    )




    payload.update(

        {

        "exp":expire

        }

    )






    token = jwt.encode(

        payload,

        settings.SECRET_KEY,

        algorithm=settings.ALGORITHM

    )




    return token







# ============================
# VERIFY TOKEN
# ============================



def verify_token(

    token:str

):


    try:



        payload = jwt.decode(

            token,

            settings.SECRET_KEY,

            algorithms=[

                settings.ALGORITHM

            ]

        )



        return payload





    except JWTError:



        raise HTTPException(


            status_code=status.HTTP_401_UNAUTHORIZED,


            detail="Invalid token"


        )