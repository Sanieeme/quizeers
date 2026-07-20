const password =
document.getElementById("password");


const showPassword =
document.getElementById("showPassword");



if(showPassword){


showPassword.addEventListener(
"click",
()=>{


if(password.type === "password"){


password.type="text";


showPassword.innerHTML =
'<i class="bi bi-eye-slash"></i>';


}

else{


password.type="password";


showPassword.innerHTML =
'<i class="bi bi-eye"></i>';


}


});


}




const loginForm =
document.getElementById("loginForm");



if(loginForm){


loginForm.addEventListener(
"submit",
(e)=>{


e.preventDefault();



const email =
document.getElementById("email").value;



const password =
document.getElementById("password").value;




console.log({

email,

password

});



/*

Later:

fetch backend API

POST /api/login

*/


alert(
"Login API will connect here"
);



});


}
const registerPassword =
document.getElementById("registerPassword");


const showRegisterPassword =
document.getElementById("showRegisterPassword");


if(showRegisterPassword){


showRegisterPassword.addEventListener(
"click",
()=>{


if(registerPassword.type === "password"){

registerPassword.type="text";


showRegisterPassword.innerHTML =
'<i class="bi bi-eye-slash"></i>';

}

else{

registerPassword.type="password";


showRegisterPassword.innerHTML =
'<i class="bi bi-eye"></i>';

}


});


}






const registerForm =
document.getElementById("registerForm");



if(registerForm){


registerForm.addEventListener(
"submit",
(e)=>{


e.preventDefault();



const password =
document.getElementById("registerPassword").value;


const confirm =
document.getElementById("confirmPassword").value;




if(password !== confirm){


alert(
"Passwords do not match"
);


return;


}




const user = {


firstName:
document.getElementById("firstName").value,


lastName:
document.getElementById("lastName").value,


email:
document.getElementById("registerEmail").value,


username:
document.getElementById("username").value,


country:
document.getElementById("country").value


};



console.log(user);



// Later connect:

// fetch("https://backend-url/api/register",
// {
// method:"POST",
// headers:{
// "Content-Type":"application/json"
// },
// body:JSON.stringify(user)
// }
// )


alert(
"Registration ready for backend connection"
);



});


}