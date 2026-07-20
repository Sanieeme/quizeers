const searchInput =
document.getElementById("searchQuiz");


const category =
document.getElementById("categoryFilter");


const quizzes =
document.querySelectorAll(".quiz-item");



function filterQuiz(){


let search =
searchInput.value.toLowerCase();


let selected =
category.value;



quizzes.forEach(card=>{


let text =
card.innerText.toLowerCase();


let cardCategory =
card.dataset.category;



let matchesSearch =
text.includes(search);



let matchesCategory =
selected==="all" ||
cardCategory===selected;



if(matchesSearch && matchesCategory){

card.style.display="block";

}

else{

card.style.display="none";

}


});


}



searchInput.addEventListener(
"keyup",
filterQuiz
);



category.addEventListener(
"change",
filterQuiz
);