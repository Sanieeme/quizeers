"""
Quiz Business Logic

Handles quiz operations.
"""





def create_quiz(
    db,
    quiz_data
):


    quiz = {


        "title":
        quiz_data.title,


        "description":
        quiz_data.description,


        "category":
        quiz_data.category,


        "difficulty":
        quiz_data.difficulty


    }



    # Later:
    # db.add(quiz)


    return quiz











def get_all_quizzes(db):


    """
    Return all active quizzes
    """


    return []










def calculate_score(
    questions,
    answers
):


    score = 0



    total = len(
        questions
    )



    for question in questions:


        user_answer = answers.get(
            str(question.id)
        )


        if user_answer == question.correct_answer:


            score += 1





    percentage = (

        score / total

    ) * 100




    return percentage