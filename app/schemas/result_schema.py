"""
Result Schemas
"""


from pydantic import BaseModel


from datetime import datetime





# ============================
# SUBMIT QUIZ
# ============================


class ResultCreate(BaseModel):


    quiz_id:int


    answers:dict







# ============================
# RESULT RESPONSE
# ============================


class ResultResponse(BaseModel):


    id:int


    quiz_id:int


    score:float


    completed_at:datetime



    class Config:

        from_attributes=True







# ============================
# LEADERBOARD
# ============================


class LeaderboardResponse(BaseModel):


    username:str


    total_score:float


    quizzes_completed:int