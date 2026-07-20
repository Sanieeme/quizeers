"""
QuizVerse Configuration

Handles:
- Environment variables
- Database configuration
- Security settings
- Application settings
"""


from pydantic_settings import BaseSettings, SettingsConfigDict



class Settings(BaseSettings):

    """
    Application Settings
    """



    # Application

    APP_NAME: str = "QuizVerse API"

    APP_VERSION: str = "1.0.0"

    ENVIRONMENT: str = "development"




    # Database

    DATABASE_URL: str = (
        "postgresql://"
        "postgres:"
        "password@localhost:5432/"
        "quizverse"
    )




    # Security

    SECRET_KEY: str = (
        "change-this-secret-key"
    )


    ALGORITHM: str = "HS256"


    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60





    # CORS

    FRONTEND_URL: str = (
        "http://localhost:5500"
    )




    model_config = SettingsConfigDict(

        env_file=".env",

        env_file_encoding="utf-8"

    )





settings = Settings()