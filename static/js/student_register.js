document.querySelectorAll(".bf-password-toggle").forEach(function (button) {
    button.addEventListener("click", function () {
        const input = document.getElementById(button.dataset.target);
        const visible = input.type === "password";
        const label = input.id === "confirm_password" ? "confirmation password" : "password";
        input.type = visible ? "text" : "password";
        button.textContent = visible ? "Hide" : "Show";
        button.setAttribute("aria-label", (visible ? "Hide " : "Show ") + label);
        button.setAttribute("aria-pressed", String(visible));
    });
});

const registrationErrors = document.getElementById("registration-errors");
if (registrationErrors) {
    registrationErrors.focus();
}
