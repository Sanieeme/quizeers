"""
Recommendation Engine

Future AI/Data Engineering feature.
"""







def recommend_quizzes(
    user_results
):


    recommendations = []




    average_score = (

        sum(
            r.score
            for r in user_results
        )

        /

        len(user_results)

    )






    if average_score < 60:


        recommendations.append(

            "Beginner Programming Quiz"

        )


    elif average_score < 80:


        recommendations.append(

            "Intermediate Challenges"

        )


    else:


        recommendations.append(

            "Advanced Problems"

        )





    return recommendations