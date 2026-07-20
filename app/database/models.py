"""
QuizVerse Database Models

Contains all database tables.
"""


from sqlalchemy import (

    Column,

    Integer,

    String,

    Boolean,

    Text,

    DateTime,

    ForeignKey,

    Float

)


from sqlalchemy.orm import relationship


from datetime import datetime



from app.database.connection import Base







# ============================
# USERS TABLE
# ============================


class User(Base):


    __tablename__ = "users"



    id = Column(

        Integer,

        primary_key=True,

        index=True

    )



    username = Column(

        String(100),

        nullable=False

    )



    email = Column(

        String(150),

        unique=True,

        index=True,

        nullable=False

    )



    password_hash = Column(

        String(255),

        nullable=False

    )



    role = Column(

        String(20),

        default="student"

    )



    is_active = Column(

        Boolean,

        default=True

    )



    created_at = Column(

        DateTime,

        default=datetime.utcnow

    )





    # Relationship

    results = relationship(

        "Result",

        back_populates="user"

    )









# ============================
# QUIZZES TABLE
# ============================



class Quiz(Base):


    __tablename__ = "quizzes"



    id = Column(

        Integer,

        primary_key=True

    )



    title = Column(

        String(200),

        nullable=False

    )



    description = Column(

        Text

    )



    category = Column(

        String(100)

    )



    difficulty = Column(

        String(50),

        default="Medium"

    )



    created_at = Column(

        DateTime,

        default=datetime.utcnow

    )





    questions = relationship(

        "Question",

        back_populates="quiz",

        cascade="all, delete"

    )









# ============================
# QUESTIONS TABLE
# ============================



class Question(Base):


    __tablename__ = "questions"



    id = Column(

        Integer,

        primary_key=True

    )



    quiz_id = Column(

        Integer,

        ForeignKey(
            "quizzes.id"
        )

    )



    question_text = Column(

        Text,

        nullable=False

    )



    correct_answer = Column(

        String(255)

    )





    quiz = relationship(

        "Quiz",

        back_populates="questions"

    )



    answers = relationship(

        "Answer",

        back_populates="question",

        cascade="all, delete"

    )









# ============================
# ANSWERS TABLE
# ============================



class Answer(Base):


    __tablename__ = "answers"



    id = Column(

        Integer,

        primary_key=True

    )



    question_id = Column(

        Integer,

        ForeignKey(
            "questions.id"
        )

    )



    answer_text = Column(

        String(255)

    )



    is_correct = Column(

        Boolean,

        default=False

    )





    question = relationship(

        "Question",

        back_populates="answers"

    )









# ============================
# RESULTS TABLE
# ============================



class Result(Base):


    __tablename__ = "results"



    id = Column(

        Integer,

        primary_key=True

    )



    user_id = Column(

        Integer,

        ForeignKey(
            "users.id"
        )

    )



    quiz_id = Column(

        Integer,

        ForeignKey(
            "quizzes.id"
        )

    )



    score = Column(

        Float

    )



    completed_at = Column(

        DateTime,

        default=datetime.utcnow

    )





    user = relationship(

        "User",

        back_populates="results"

    )



    quiz = relationship(

        "Quiz"

    )









# ============================
# ACTIVITY LOGS
# ============================



class ActivityLog(Base):


    __tablename__ = "activity_logs"



    id = Column(

        Integer,

        primary_key=True

    )



    user_id = Column(

        Integer,

        ForeignKey(
            "users.id"
        )

    )



    action = Column(

        String(255)

    )



    created_at = Column(

        DateTime,

        default=datetime.utcnow

    )