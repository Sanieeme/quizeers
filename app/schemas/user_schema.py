"""
User Schemas

Controls user API data.
"""


from pydantic import BaseModel, EmailStr

from datetime import datetime





# ============================
# USER REGISTRATION
# ============================


class UserCreate(BaseModel):


    username: str


    email: EmailStr


    password: str







# ============================
# LOGIN
# ============================


class UserLogin(BaseModel):


    email: EmailStr


    password: str







# ============================
# USER RESPONSE
# ============================


class UserResponse(BaseModel):


    id: int


    username: str


    email: EmailStr


    role: str


    is_active: bool


    created_at: datetime





    class Config:

        from_attributes = True







# ============================
# UPDATE PROFILE
# ============================


class UserUpdate(BaseModel):


    username: str | None = None


    email: EmailStr | None = None