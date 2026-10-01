console.log("Operation Black Falcon SOC CTF loaded successfully.");

document.addEventListener("DOMContentLoaded", function () {
    const currentPath = window.location.pathname;
    const links = document.querySelectorAll(".sidebar a");

    links.forEach(link => {
        if (link.getAttribute("href") === currentPath) {
            link.classList.add("active");
        }
    });
});
