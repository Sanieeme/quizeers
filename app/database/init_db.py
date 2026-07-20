from app.database.connection import engine
from app.database.models import Base



def create_tables():

    print("Creating database tables...")


    Base.metadata.create_all(
        bind=engine
    )


    print("Tables created successfully")



if __name__ == "__main__":

    create_tables()