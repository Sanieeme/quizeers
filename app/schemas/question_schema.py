"""
Question Schemas
"""


from pydantic import BaseModel





# ============================
# ANSWERS
# ============================


class AnswerCreate(BaseModel):


    answer_text: str


    is_correct: bool







class AnswerResponse(BaseModel):


    id: int


    answer_text: str


    is_correct: bool



    class Config:

        from_attributes=True







# ============================
# QUESTIONS
# ============================


class QuestionCreate(BaseModel):


    question_text: str


    correct_answer: str


    answers: list[AnswerCreate]








class QuestionResponse(BaseModel):


    id: int


    question_text: str


    answers: list[AnswerResponse]



    class Config:

        from_attributes=True