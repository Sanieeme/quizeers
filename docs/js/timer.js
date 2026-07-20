let seconds = 600;


const timer =
document.getElementById("time");



function updateTimer(){


let minutes =
Math.floor(seconds / 60);



let remaining =
seconds % 60;



timer.innerHTML =
`${minutes}:${remaining < 10 ? "0":""}${remaining}`;



if(seconds <=0){


alert(
"Time finished! Quiz submitted."
);


window.location.href =
"results.html";


}



seconds--;


}



setInterval(
updateTimer,
1000
);