'use strict'; 

const split_url = window.location.href.split('/'); 

const inputs = document.querySelectorAll('.form-check-input');
console.log(split_url)
for (let i = 0; i < inputs.length; i++) {
    inputs[i].addEventListener("input", () => {
        if (split_url[3] == 'playlists') {
            window.location.href = `${split_url[0]}//${split_url[2]}/playlist/${inputs[i].value}`
        } else {
            window.location.href = inputs[i].value; 
        }
    }); 
}