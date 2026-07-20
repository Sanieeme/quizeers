"""
QuizVerse Helper Functions

Reusable functions used
throughout the application.
"""



from datetime import datetime





# ============================
# DATE FUNCTIONS
# ============================


def format_date(
    date: datetime
):

    """
    Convert datetime object
    into readable format.
    """


    return date.strftime(

        "%d %B %Y"

    )









# ============================
# API RESPONSE FORMATTER
# ============================


def success_response(

    message,

    data=None

):

    """
    Standard API response format.
    """



    return {


        "success": True,


        "message": message,


        "data": data


    }









def error_response(

    message

):


    return {


        "success":False,


        "message":message


    }









# ============================
# PAGINATION
# ============================


def paginate(

    items,

    page:int =1,

    limit:int =10

):


    """
    Used for:

    - quizzes
    - users
    - results

    """



    start = (

        page - 1

    ) * limit




    end = start + limit





    return items[start:end]









# ============================
# SCORE CALCULATION
# ============================


def calculate_percentage(

    correct,

    total

):


    if total == 0:

        return 0





    return round(

        (correct / total) * 100,

        2

    )









# ============================
# LEVEL SYSTEM
# ============================


def calculate_level(

    xp:int

):


    """
    Gamification system.

    Example:

    0-1000 XP
    Beginner

    1000-5000 XP
    Intermediate

    5000+
    Expert

    """



    if xp < 1000:


        return "Beginner"




    elif xp < 5000:


        return "Intermediate"





    else:


        return "Expert"









# ============================
# USER ACTIVITY LOGGER
# ============================


def create_activity_log(

    user_id,

    action

):


    return {


        "user_id":

        user_id,


        "action":

        action,


        "created_at":

        datetime.utcnow()


    }