"""
QuizVerse Database Connection

Handles:
- PostgreSQL connection
- SQLAlchemy engine
- Database sessions
"""


from sqlalchemy import create_engine

from sqlalchemy.orm import (
    sessionmaker,
    declarative_base
)


from app.config import settings





# ============================
# DATABASE ENGINE
# ============================


engine = create_engine(

    settings.DATABASE_URL,

    pool_pre_ping=True

)







# ============================
# DATABASE SESSION
# ============================


SessionLocal = sessionmaker(

    autocommit=False,

    autoflush=False,

    bind=engine

)







# ============================
# BASE MODEL CLASS
# ============================


Base = declarative_base()







# ============================
# DATABASE DEPENDENCY
# ============================


def get_db():

    """
    Creates database session
    for every API request.
    """


    db = SessionLocal()


    try:

        yield db


    finally:

        db.close()