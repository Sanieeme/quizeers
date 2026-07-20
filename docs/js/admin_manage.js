/*
    QuizVerse Admin Quiz Management

    Features:
    - Search quizzes
    - Filter categories
    - Delete quizzes
    - Connect with backend API
*/



const ADMIN_API =
"https://your-backend-api.com/api/admin";




// ===============================
// LOAD QUIZZES
// ===============================


async function loadQuizzes(){



try{


const response =
await fetch(

ADMIN_API +
"/quizzes"

);



const quizzes =
await response.json();



displayQuizzes(
quizzes
);



}



catch(error){


console.log(
"Using demo data"
);


}



}









// ===============================
// DISPLAY QUIZZES
// ===============================


function displayQuizzes(
quizzes
){



const table =
document.getElementById(
"quizTable"
);



if(!table)
return;




table.innerHTML="";




quizzes.forEach(
quiz=>{



table.innerHTML += `



<tr class="quiz-row">


<td>

${quiz.title}

</td>



<td>

${quiz.category}

</td>



<td>

<span class="badge bg-primary">

${quiz.difficulty}

</span>

</td>



<td>

${quiz.questions}

</td>



<td>


<span class="badge bg-success">

Active

</span>


</td>



<td>


<button

onclick="editQuiz(${quiz.id})"

class="btn btn-warning btn-sm">


<i class="bi bi-pencil"></i>


</button>




<button

onclick="deleteQuiz(${quiz.id})"

class="btn btn-danger btn-sm">


<i class="bi bi-trash"></i>


</button>



</td>



</tr>



`;



});



}









// ===============================
// DELETE QUIZ
// ===============================



async function deleteQuiz(id){



const confirmDelete =
confirm(
"Delete this quiz?"
);



if(!confirmDelete)
return;





await fetch(

ADMIN_API +
"/quizzes/" +
id,


{


method:"DELETE"


}


);




alert(
"Quiz deleted"
);



loadQuizzes();



}









// ===============================
// EDIT QUIZ
// ===============================


function editQuiz(id){



localStorage.setItem(
"editQuiz",
id
);



window.location.href =
"admin_edit_quiz.html";



}









// ===============================
// SEARCH
// ===============================


function searchQuiz(){



const input =
document
.getElementById(
"searchQuiz"
)
.value
.toLowerCase();





const rows =
document.querySelectorAll(
".quiz-row"
);




rows.forEach(
row=>{



if(
row.innerText
.toLowerCase()
.includes(input)

){


row.style.display="";


}

else{


row.style.display="none";


}


});


}








// ===============================
// INITIAL LOAD
// ===============================


document.addEventListener(

"DOMContentLoaded",

()=>{


loadQuizzes();



const search =
document.getElementById(
"searchQuiz"
);



if(search){


search.addEventListener(
"keyup",
searchQuiz
);


}


}

);