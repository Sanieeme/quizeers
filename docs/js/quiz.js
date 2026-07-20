const questions=[


{

question:"What is Python?",

answers:[

"Programming Language",

"Database",

"Browser",

"Operating System"

]

},


{

question:"Which keyword creates a function?",

answers:[

"class",

"function",

"def",

"method"

]

},


{

question:"Which data structure stores key-value pairs?",

answers:[

"List",

"Tuple",

"Dictionary",

"String"

]

}



];



let current=0;



const questionText =
document.getElementById("questionText");


const options =
document.querySelectorAll(".answer-option label");



const progress =
document.getElementById("progressBar");



const number =
document.getElementById("currentQuestion");



const next =
document.getElementById("nextBtn");


const previous =
document.getElementById("previousBtn");


const submit =
document.getElementById("submitBtn");




function loadQuestion(){



let q =
questions[current];



questionText.innerHTML =
q.question;



options.forEach(
(option,index)=>{


option.innerHTML =
`${String.fromCharCode(65+index)}. ${q.answers[index]}`;


});



number.innerHTML =
current+1;



let percentage =
((current+1)/questions.length)*100;



progress.style.width =
percentage+"%";


progress.innerHTML =
Math.round(percentage)+"%";




if(current===questions.length-1){


next.classList.add("d-none");

submit.classList.remove("d-none");


}



else{


next.classList.remove("d-none");

submit.classList.add("d-none");


}


}




next.onclick=()=>{


if(current < questions.length-1){

current++;

loadQuestion();

}


};



previous.onclick=()=>{


if(current>0){

current--;

loadQuestion();

}


};




submit.onclick=()=>{


window.location.href=
"results.html";


};




loadQuestion();