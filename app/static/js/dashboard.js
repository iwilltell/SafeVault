
async function loadUser() {
    try {
        const response = await fetch("/auth/me");

        if (!response.ok) {
            window.location.href = "/";
            return;
        }

        const user = await response.json();
        document.getElementById("username").textContent = user.username;
    } catch (error) {
        console.error("Unable to load account information:", error);
    }
}

document.getElementById("logoutButton").addEventListener("click", async () => {
    try {
        const response = await fetch("/auth/logout", {
            method: "POST"
        });

        if (response.ok) {
            window.location.href = "/";
        } else {
            alert("Unable to log out. Please try again.");
        }
    } catch (error) {
        alert("Unable to connect to SafeVault.");
    }
});

loadUser();
