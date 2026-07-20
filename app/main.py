"""
QuizVerse API

Main application entry point.
"""


from fastapi import FastAPI

from fastapi.middleware.cors import CORSMiddleware


from app.config import settings



# Routers

from app.routers import (
    auth,
    users,
    quizzes,
    results,
    leaderboard,
    admin
)







app = FastAPI(


    title=settings.APP_NAME,


    version=settings.APP_VERSION,


    description="""

    QuizVerse Learning Platform API


    Features:

    - User authentication

    - Quiz management

    - Results tracking

    - Leaderboard system

    - Admin dashboard

    - Analytics pipeline


    """

)







# ============================
# CORS CONFIGURATION
# ============================


app.add_middleware(


    CORSMiddleware,


    allow_origins=[

        settings.FRONTEND_URL,


        "http://localhost:5500",

        "http://127.0.0.1:5500"

    ],


    allow_credentials=True,


    allow_methods=["*"],


    allow_headers=["*"],


)







# ============================
# ROUTES
# ============================



app.include_router(

    auth.router,

    prefix="/api/auth",

    tags=["Authentication"]

)



app.include_router(

    users.router,

    prefix="/api/users",

    tags=["Users"]

)



app.include_router(

    quizzes.router,

    prefix="/api/quizzes",

    tags=["Quizzes"]

)



app.include_router(

    results.router,

    prefix="/api/results",

    tags=["Results"]

)



app.include_router(

    leaderboard.router,

    prefix="/api/leaderboard",

    tags=["Leaderboard"]

)



app.include_router(

    admin.router,

    prefix="/api/admin",

    tags=["Admin"]

)









# ============================
# HEALTH CHECK
# ============================



@app.get("/")

def home():

    return {


        "application":
        settings.APP_NAME,


        "version":
        settings.APP_VERSION,


        "status":
        "running"


    }







@app.get("/health")

def health_check():

    return {


        "status":
        "healthy",


        "environment":
        settings.ENVIRONMENT


    }