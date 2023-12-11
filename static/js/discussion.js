const button = document.querySelector('.discussion-post-btn'); 
const div = document.querySelector('.hidden'); 
console.log(div); 
console.log(button); 
button.addEventListener("click", () => {
    if (div.classList.contains('hidden')) {
        div.classList.remove('hidden'); 
    } else {
        div.classList.add('hidden'); 
    }
}); 