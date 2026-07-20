"""
Authentication Dependencies

Used to protect API routes.
"""


from fastapi import Depends, HTTPException


from fastapi.security import OAuth2PasswordBearer



from app.security.jwt import verify_token





oauth2_scheme = OAuth2PasswordBearer(

    tokenUrl="/api/auth/login"

)








def current_user(

    token:str = Depends(
        oauth2_scheme
    )

):


    user = verify_token(
        token
    )



    return user







def admin_required(

    user = Depends(
        current_user
    )

):


    if user.get(
        "role"
    ) != "admin":


        raise HTTPException(

            status_code=403,

            detail="Admin access required"

        )



    return user