"""
Quiz Schemas
"""


from pydantic import BaseModel


from datetime import datetime


from app.schemas.question_schema import (

    QuestionResponse

)







# ============================
# CREATE QUIZ
# ============================


class QuizCreate(BaseModel):


    title: str


    description: str | None = None


    category: str


    difficulty: str







# ============================
# QUIZ RESPONSE
# ============================


class QuizResponse(BaseModel):


    id: int


    title: str


    description: str | None


    category: str


    difficulty: str


    created_at: datetime




    class Config:

        from_attributes=True







# ============================
# FULL QUIZ
# ============================


class QuizDetailResponse(BaseModel):


    id:int


    title:str


    description:str | None


    questions:list[QuestionResponse]



    class Config:

        from_attributes=True