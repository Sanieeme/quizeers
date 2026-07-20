/*
    Leaderboard System

    Future API:

    GET /api/leaderboard

*/


async function loadLeaderboard(){



// Future backend connection


const leaderboard = [


{

name:"Sarah",

xp:9800

},


{

name:"John",

xp:8500

},


{

name:"Mary",

xp:7600

}


];



console.log(
"Leaderboard Data",
leaderboard
);



}



document.addEventListener(

"DOMContentLoaded",

loadLeaderboard

);