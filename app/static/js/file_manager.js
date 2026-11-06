
const fileInput = document.getElementById("fileInput");
const uploadButton = document.getElementById("uploadButton");
const uploadArea = document.getElementById("uploadArea");
const selectedFile = document.getElementById("selectedFile");
const fileTableBody = document.getElementById("fileTableBody");
const statusMessage = document.getElementById("statusMessage");

const shareModal = document.getElementById("shareModal");
const shareForm = document.getElementById("shareForm");
const shareMessage = document.getElementById("shareMessage");

let currentShareFile = null;

function showStatus(element, message, type) {
    element.textContent = message;
    element.className = `status-message show ${type}`;
}

function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) {
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDate(value) {
    if (!value) return "—";

    const date = new Date(value.replace(" ", "T") + "Z");

    if (Number.isNaN(date.getTime())) return value;

    return date.toLocaleDateString();
}

function makeCell(text, className = "") {
    const cell = document.createElement("td");
    cell.textContent = text;
    if (className) cell.className = className;
    return cell;
}

async function loadFiles() {
    fileTableBody.replaceChildren();

    const loading = document.createElement("tr");
    const loadingCell = makeCell("Loading your files...", "empty-state");
    loadingCell.colSpan = 6;
    loading.appendChild(loadingCell);
    fileTableBody.appendChild(loading);

    try {
        const response = await fetch("/files");

        if (response.status === 401) {
            window.location.href = "/";
            return;
        }

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to load files.");
        }

        const files = data.files || [];

        document.getElementById("totalFiles").textContent = files.length;

        const storage = files.reduce(
            (total, file) => total + Number(file.file_size || 0), 0
        );

        document.getElementById("totalStorage").textContent = formatSize(storage);

        document.getElementById("encryptedFiles").textContent =
            files.filter(file => file.is_encrypted).length;

        fileTableBody.replaceChildren();

        if (files.length === 0) {
            const row = document.createElement("tr");
            const cell = makeCell("No files yet. Upload your first file above.");
            cell.colSpan = 6;
            cell.className = "empty-state";
            row.appendChild(cell);
            fileTableBody.appendChild(row);
            return;
        }

        files.forEach(file => {
            const row = document.createElement("tr");

            const nameCell = document.createElement("td");
            const name = document.createElement("div");
            name.className = "file-name";
            name.textContent = file.original_name;

            const type = document.createElement("div");
            type.className = "file-type";
            type.textContent = file.mime_type || "Unknown file type";

            nameCell.append(name, type);

            const accessCell = document.createElement("td");
            const access = document.createElement("span");
            access.className = "access-tag";
            access.textContent = file.access_type || "owner";
            accessCell.appendChild(access);

            const encryptionCell = document.createElement("td");
            const encryption = document.createElement("span");
            encryption.className = "encryption-tag";
            encryption.textContent = file.is_encrypted ? "Encrypted" : "Not encrypted";
            encryptionCell.appendChild(encryption);

            const actionsCell = document.createElement("td");
            const actions = document.createElement("div");
            actions.className = "action-group";

            const downloadButton = document.createElement("button");
            downloadButton.className = "action-button";
            downloadButton.textContent = "Download";
            downloadButton.addEventListener("click", () => {
                window.location.href = `/files/${file.id}/download`;
            });
            actions.appendChild(downloadButton);

            if (file.access_type === "owner") {
                const shareButton = document.createElement("button");
                shareButton.className = "action-button";
                shareButton.textContent = "Share";
                shareButton.addEventListener("click", () => openShareModal(file));
                actions.appendChild(shareButton);
            }

            actionsCell.appendChild(actions);

            row.append(
                nameCell,
                makeCell(formatSize(file.file_size)),
                accessCell,
                encryptionCell,
                makeCell(formatDate(file.created_at)),
                actionsCell
            );

            fileTableBody.appendChild(row);
        });

    } catch (error) {
        fileTableBody.replaceChildren();

        const row = document.createElement("tr");
        const cell = makeCell(error.message, "empty-state");
        cell.colSpan = 6;
        row.appendChild(cell);
        fileTableBody.appendChild(row);
    }
}

fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];

    selectedFile.textContent = file
        ? `Selected: ${file.name} (${formatSize(file.size)})`
        : "";

    uploadButton.disabled = !file;
});

uploadButton.addEventListener("click", async () => {
    const file = fileInput.files[0];

    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    uploadButton.disabled = true;
    uploadButton.textContent = "Scanning and uploading...";

    try {
        const response = await fetch("/files/upload", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Upload failed.");
        }

        showStatus(
            statusMessage,
            "File uploaded, scanned and encrypted successfully.",
            "success"
        );

        fileInput.value = "";
        selectedFile.textContent = "";

        await loadFiles();

    } catch (error) {
        showStatus(statusMessage, error.message, "error");
    } finally {
        uploadButton.disabled = !fileInput.files.length;
        uploadButton.textContent = "Upload securely";
    }
});

function openShareModal(file) {
    currentShareFile = file;

    document.getElementById("shareFileName").textContent =
        `Sharing: ${file.original_name}`;

    document.getElementById("shareUsername").value = "";
    document.getElementById("sharePermission").value = "read";

    shareMessage.className = "status-message";
    shareModal.classList.add("open");
}

document.getElementById("closeModal").addEventListener("click", () => {
    shareModal.classList.remove("open");
});

shareModal.addEventListener("click", event => {
    if (event.target === shareModal) {
        shareModal.classList.remove("open");
    }
});

shareForm.addEventListener("submit", async event => {
    event.preventDefault();

    if (!currentShareFile) return;

    const username = document.getElementById("shareUsername").value.trim();
    const permission = document.getElementById("sharePermission").value;

    try {
        const response = await fetch(
            `/files/${currentShareFile.id}/share`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ username, permission })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to share file.");
        }

        showStatus(shareMessage, data.message, "success");

    } catch (error) {
        showStatus(shareMessage, error.message, "error");
    }
});

document.getElementById("refreshButton").addEventListener("click", loadFiles);

// Basic drag-and-drop support.
uploadArea.addEventListener("dragover", event => {
    event.preventDefault();
    uploadArea.classList.add("drag-over");
});

uploadArea.addEventListener("dragleave", () => {
    uploadArea.classList.remove("drag-over");
});

uploadArea.addEventListener("drop", event => {
    event.preventDefault();
    uploadArea.classList.remove("drag-over");

    if (event.dataTransfer.files.length) {
        fileInput.files = event.dataTransfer.files;
        fileInput.dispatchEvent(new Event("change"));
    }
});

loadFiles();
