
const loginForm = document.getElementById("loginForm");
const loginButton = document.getElementById("loginButton");
const messageBox = document.getElementById("message");

function showMessage(message, type) {
    messageBox.textContent = message;
    messageBox.className = `message ${type}`;
}

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    loginButton.disabled = true;
    loginButton.querySelector("span:first-child").textContent = "Authenticating...";
    messageBox.className = "message";

    try {
        const response = await fetch("/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (!response.ok) {
            showMessage(data.error || "Login failed.", "error");
            return;
        }

        if (data.requires_2fa) {
            window.location.href = "/verify-2fa";
            return;
        }

        window.location.href = "/dashboard";

    } catch (error) {
        showMessage("Unable to connect to SafeVault. Please try again.", "error");
    } finally {
        loginButton.disabled = false;
        loginButton.querySelector("span:first-child").textContent = "Sign in securely";
    }
});
