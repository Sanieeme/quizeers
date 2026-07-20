const search =
document.getElementById(
"searchUser"
);


const role =
document.getElementById(
"roleFilter"
);



const rows =
document.querySelectorAll(
".user-row"
);





function filterUsers(){


let text =
search.value.toLowerCase();



let selectedRole =
role.value;



rows.forEach(row=>{


let rowText =
row.innerText.toLowerCase();



let rowRole =
row.querySelector(".role")
.innerText;



let matchText =
rowText.includes(text);



let matchRole =
selectedRole==="all"
||
rowRole===selectedRole;




if(matchText && matchRole){

row.style.display="";

}

else{

row.style.display="none";

}



});


}





search.addEventListener(
"keyup",
filterUsers
);



role.addEventListener(
"change",
filterUsers
);








// CHANGE ROLE


document.querySelectorAll(
".role-btn"
)
.forEach(button=>{


button.addEventListener(
"click",
()=>{


let badge =
button
.closest("tr")
.querySelector(".role");




if(
badge.innerText==="Student"
){

badge.innerText="Admin";

badge.className=
"badge bg-danger role";


}

else{


badge.innerText="Student";

badge.className=
"badge bg-primary role";


}



});


});








// DELETE USER


document.querySelectorAll(
".delete-btn"
)
.forEach(button=>{


button.addEventListener(
"click",
()=>{


if(
confirm(
"Delete this user?"
)
){


button.closest("tr").remove();


}



});


});