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

function redirectToPost(event) {
    const clickedElement = event.target;
    const postIdElement = clickedElement.closest('.discussion-card-container').querySelector('#post_id');
    
    if (postIdElement) {
        const postId = postIdElement.textContent.trim();
        window.location.href = `${window.location.origin}/post/${postId}`;
    }
}
