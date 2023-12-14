'use strict';

const navLinks = document.querySelectorAll('.navItem');

navLinks.forEach(navLink => {
    navLink.addEventListener('click', () => {
        document.querySelector('.active').classList.remove('active');
        navLink.classList.add('active');
    });
});


