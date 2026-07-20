// Temporary demo data
// Later this will come from Flask API


const result = {


score:85,

correct:17,

wrong:3,

time:"08:20"


};





document.getElementById("score")
.innerHTML =
result.score+"%";



document.getElementById("correct")
.innerHTML =
result.correct;



document.getElementById("wrong")
.innerHTML =
result.wrong;



document.getElementById("timeTaken")
.innerHTML =
result.time;







const message =
document.getElementById("message");



if(result.score >=80){


message.innerHTML =
"Excellent Work! 🏆";


}

else if(result.score >=50){


message.innerHTML =
"Good Job! Keep Improving 💪";


}

else{


message.innerHTML =
"Keep Practicing! You Can Do Better 🚀";


}