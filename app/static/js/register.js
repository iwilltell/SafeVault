
const registerForm = document.getElementById("registerForm");
const registerButton = document.getElementById("registerButton");
const registerMessage = document.getElementById("registerMessage");

function showMessage(message, type) {
    registerMessage.textContent = message;
    registerMessage.className = `message show ${type}`;
}

registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const confirmPassword =
        document.getElementById("confirmPassword").value;

    if (username.length < 3) {
        showMessage("Username must contain at least 3 characters.", "error");
        return;
    }

    if (password.length < 8) {
        showMessage("Password must contain at least 8 characters.", "error");
        return;
    }

    if (password !== confirmPassword) {
        showMessage("Passwords do not match.", "error");
        return;
    }

    registerButton.disabled = true;
    registerButton.textContent = "Creating account...";

    try {
        const response = await fetch("/auth/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username,
                email,
                password
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || data.message || "Registration failed."
            );
        }

        showMessage(
            "Account created successfully! Redirecting to login...",
            "success"
        );

        registerForm.reset();

        setTimeout(() => {
            window.location.href = "/";
        }, 1500);

    } catch (error) {
        showMessage(error.message, "error");

    } finally {
        registerButton.disabled = false;
        registerButton.textContent = "Create Account →";
    }
});
