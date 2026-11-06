
const form = document.getElementById("loginOtpForm");
const messageBox = document.getElementById("verifyMessage");
const verifyButton = document.getElementById("verifyButton");

function showMessage(message, type = "error") {
    messageBox.textContent = message;
    messageBox.className = `message show ${type}`;
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const otp = document.getElementById("loginOtp").value.trim();

    if (!/^\d{6}$/.test(otp)) {
        showMessage("Enter a valid six-digit code.");
        return;
    }

    verifyButton.disabled = true;
    verifyButton.textContent = "Verifying...";

    try {
        const response = await fetch("/auth/2fa/verify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ otp })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Verification failed.");
        }

        showMessage(data.message, "success");

        setTimeout(() => {
            window.location.href = "/dashboard";
        }, 800);

    } catch (error) {
        showMessage(error.message);
        document.getElementById("loginOtp").value = "";

    } finally {
        verifyButton.disabled = false;
        verifyButton.textContent = "Verify and continue →";
    }
});
