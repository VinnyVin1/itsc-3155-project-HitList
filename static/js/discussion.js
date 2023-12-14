const button = document.querySelector('.discussion-post-btn'); 
const div = document.querySelector('.hidden'); 
// small script just adds and removes the hidden class on the new post div in the discussion page
button.addEventListener("click", () => {
    if (div.classList.contains('hidden')) {
        div.classList.remove('hidden'); 
    } else {
        div.classList.add('hidden'); 
    }
}); 