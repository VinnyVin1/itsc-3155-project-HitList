'use strict'; 

// shows and hides the 
const buttons = document.querySelectorAll('.settings-btn'); 
const divs = document.querySelectorAll('.prof-settings-form-group'); 
const webpages = document.querySelectorAll('a');

for (let i = 0; i < buttons.length; i++) {
    buttons[i].addEventListener("click", () => {
        if (divs[i].classList.contains('hidden')) {
            divs.forEach((div) => {div.classList.add('hidden')}); 
            divs[i].classList.remove('hidden'); 
        } else {
            divs[i].classList.add('hidden'); 
        }
    }); 
}

window.addEventListener('DOMContentLoaded', hidePage);

function hidePage() {
    webpages.forEach(page => {
        if (page.classList.contains('hide')) {
            page.classList.add('hidden');
        }
    });
}