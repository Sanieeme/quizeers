// Temporary profile data
// Later loaded from API


const user = {


name:"Sarah Johnson",

email:"sarah@email.com",


completed:42,


average:"87%"


};



document.getElementById(
"username"
).innerHTML =
user.name;



console.log(
"Profile loaded",
user
);