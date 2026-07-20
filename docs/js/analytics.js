// Category Attempts Chart


new Chart(

document.getElementById(
"categoryChart"
),


{


type:"bar",


data:{


labels:[

"Programming",

"Data Engineering",

"Science",

"Math"

],



datasets:[{

label:"Attempts",

data:[1200,900,700,400]

}]


}



}

);








// Score Chart


new Chart(

document.getElementById(
"scoreChart"
),


{


type:"line",


data:{


labels:[

"Jan",

"Feb",

"Mar",

"Apr",

"May"

],



datasets:[{


label:"Average Score",


data:[65,70,72,78,85]


}]



}



}


);