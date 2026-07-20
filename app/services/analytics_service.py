"""
Analytics Service

Used by Data Engineering pipelines.
"""





def calculate_user_statistics(
    results
):


    total_quizzes = len(
        results
    )



    if total_quizzes == 0:


        return {


            "completed":0,

            "average_score":0

        }





    average = sum(

        r.score

        for r in results

    ) / total_quizzes





    return {


        "completed":
        total_quizzes,


        "average_score":
        round(
            average,
            2
        )


    }











def most_popular_quizzes(
    results
):


    quiz_count = {}



    for result in results:


        quiz = result.quiz_id



        quiz_count[quiz] = (

            quiz_count.get(
                quiz,
                0
            )

            +1

        )



    return quiz_count