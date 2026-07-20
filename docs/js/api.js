/*
    QuizVerse Main Frontend Application

    Responsibilities:
    - Manage user sessions
    - Connect frontend to backend API
    - Handle authentication
    - Global functions
*/


// ===============================
// API CONFIGURATION
// ===============================


const API_URL = "https://your-backend-api.com/api";


// When developing locally:
// const API_URL = "http://localhost:8000/api";




// ===============================
// USER SESSION
// ===============================


let currentUser = null;



function saveUser(user){


    localStorage.setItem(
        "quizverse_user",
        JSON.stringify(user)
    );


    currentUser = user;

}







function getUser(){


    const user =
    localStorage.getItem(
        "quizverse_user"
    );


    if(user){

        currentUser =
        JSON.parse(user);

    }


    return currentUser;

}








function logout(){


    localStorage.removeItem(
        "quizverse_user"
    );


    window.location.href =
    "login.html";


}









// ===============================
// AUTH CHECK
// ===============================



function requireLogin(){


    const user =
    getUser();



    if(!user){


        alert(
        "Please login first"
        );


        window.location.href =
        "login.html";


    }


}







function requireAdmin(){


    const user =
    getUser();



    if(
        !user ||
        user.role !== "admin"
    ){


        alert(
        "Admin access required"
        );


        window.location.href =
        "index.html";


    }



}








// ===============================
// LOAD USER DATA
// ===============================



function loadUserProfile(){


    const user =
    getUser();



    if(!user){

        return;

    }



    const username =
    document.getElementById(
        "username"
    );



    if(username){


        username.innerHTML =
        user.name;


    }


}









// ===============================
// API REQUEST FUNCTION
// ===============================



async function apiRequest(
    endpoint,
    options={}
){



    try{


        const response =
        await fetch(

            API_URL + endpoint,

            {


                headers:{


                    "Content-Type":
                    "application/json"


                },


                ...options


            }


        );





        if(!response.ok){


            throw new Error(
            "API Error"
            );


        }



        return await response.json();



    }

    catch(error){


        console.error(
            error
        );


        alert(
        "Server connection failed"
        );


    }



}








// ===============================
// LOGIN EXAMPLE
// ===============================



async function loginUser(
email,
password
){



const result =
await apiRequest(
"/auth/login",
{


method:"POST",


body:
JSON.stringify({

email,

password

})


}

);




if(result){


saveUser(result);


window.location.href =
"quizzes.html";


}



}








// ===============================
// REGISTER EXAMPLE
// ===============================



async function registerUser(data){



return await apiRequest(

"/auth/register",

{


method:"POST",

body:

JSON.stringify(data)


}


);



}









// ===============================
// PAGE INITIALIZATION
// ===============================



document.addEventListener(
"DOMContentLoaded",

()=>{


loadUserProfile();


}

);