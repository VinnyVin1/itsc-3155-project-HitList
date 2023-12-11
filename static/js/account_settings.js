'use strict'; 

const buttons = document.querySelectorAll('.settings-btn'); 
const divs = document.querySelectorAll('.prof-settings-form-group'); 

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
