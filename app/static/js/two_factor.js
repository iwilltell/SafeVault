
const statusBox = document.getElementById("statusBox");
const setupSection = document.getElementById("setupSection");
const disabledSection = document.getElementById("disabledSection");
const enabledSection = document.getElementById("enabledSection");
const messageBox = document.getElementById("message");

function showMessage(message, type = "error") {
    messageBox.textContent = message;
    messageBox.className = `message show ${type}`;
}

async function requestJson(url, method = "GET", body = null) {
    const options = {
        method,
        headers: {}
    };

    if (body !== null) {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    const data = await response.json();

    if (response.status === 401) {
        window.location.href = "/";
        throw new Error("Your session has expired.");
    }

    if (!response.ok) {
        throw new Error(data.error || "Something went wrong.");
    }

    return data;
}

async function loadStatus() {
    try {
        const user = await requestJson("/auth/me");

        statusBox.textContent = user.two_factor_enabled
            ? "Two-factor authentication is currently enabled."
            : "Two-factor authentication is currently disabled.";

        if (user.two_factor_enabled) {
            enabledSection.hidden = false;
            disabledSection.hidden = true;
            setupSection.hidden = true;
        } else {
            enabledSection.hidden = true;
            disabledSection.hidden = false;
            setupSection.hidden = true;
        }

    } catch (error) {
        statusBox.textContent = error.message;
    }
}

document.getElementById("startSetup").addEventListener("click", async () => {
    const button = document.getElementById("startSetup");
    button.disabled = true;

    try {
        const data = await requestJson("/auth/2fa/setup", "POST");

        document.getElementById("qrCode").src =
            `data:image/png;base64,${data.qr_code}`;

        document.getElementById("manualSecret").textContent =
            data.manual_secret;

        disabledSection.hidden = true;
        setupSection.hidden = false;
        statusBox.textContent = data.instructions;

    } catch (error) {
        showMessage(error.message);
    } finally {
        button.disabled = false;
    }
});

document.getElementById("copySecret").addEventListener("click", async () => {
    const secret = document.getElementById("manualSecret").textContent;

    try {
        await navigator.clipboard.writeText(secret);
        showMessage("Secret copied to clipboard.", "success");
    } catch {
        showMessage("Unable to copy. Please select and copy the secret manually.");
    }
});

document.getElementById("enableForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const button = document.getElementById("enableButton");
    const otp = document.getElementById("setupOtp").value.trim();

    if (!/^\d{6}$/.test(otp)) {
        showMessage("Enter a valid six-digit code.");
        return;
    }

    button.disabled = true;

    try {
        const data = await requestJson(
            "/auth/2fa/enable",
            "POST",
            { otp }
        );

        showMessage(data.message, "success");
        document.getElementById("enableForm").reset();

        setTimeout(loadStatus, 1200);

    } catch (error) {
        showMessage(error.message);
    } finally {
        button.disabled = false;
    }
});

document.getElementById("disableForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const password = document.getElementById("disablePassword").value;
    const otp = document.getElementById("disableOtp").value.trim();

    if (!/^\d{6}$/.test(otp)) {
        showMessage("Enter a valid six-digit authenticator code.");
        return;
    }

    if (!confirm("Are you sure you want to disable 2FA?")) {
        return;
    }

    const button = event.submitter;
    button.disabled = true;

    try {
        const data = await requestJson(
            "/auth/2fa/disable",
            "POST",
            { password, otp }
        );

        showMessage(data.message, "success");

        setTimeout(() => {
            window.location.href = "/";
        }, 1800);

    } catch (error) {
        showMessage(error.message);
    } finally {
        button.disabled = false;
    }
});

loadStatus();
