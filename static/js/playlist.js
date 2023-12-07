'use strict'; 

const split_url = window.location.href.split('/'); 

const inputs = document.querySelectorAll('.form-check-input');

for (let i = 0; i < inputs.length; i++) {
    inputs[i].addEventListener("input", () => {
        window.location.href = inputs[i].value; 
    }); 
}