const form =
document.getElementById("addQuizForm");



form.addEventListener(
"submit",
function(e){


e.preventDefault();




const quiz = {


title:
document.getElementById("title").value,


description:
document.getElementById("description").value,


category:
document.getElementById("category").value,


difficulty:
document.getElementById("difficulty").value,


questions:
document.getElementById("questions").value,


duration:
document.getElementById("duration").value,


image:
document.getElementById("image").value



};





console.log(
"New Quiz:",
quiz
);





/*

Future Flask API:

fetch(
"https://your-api.com/admin/quizzes",
{

method:"POST",

headers:{

"Content-Type":"application/json"

},

body:
JSON.stringify(quiz)

}

)


*/





alert(
"Quiz created successfully!"
);



form.reset();



});