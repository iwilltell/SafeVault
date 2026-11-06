
const activityTable = document.getElementById("activityTable");
const activityMessage = document.getElementById("activityMessage");

const searchInput = document.getElementById("searchActivity");
const eventFilter = document.getElementById("eventFilter");

const previousButton = document.getElementById("previousPage");
const nextButton = document.getElementById("nextPage");

const PAGE_SIZE = 20;

let currentPage = 0;
let allEvents = [];

function classifyEvent(eventType) {
    const type = eventType.toLowerCase();

    if (type.includes("login") || type === "logout") return "login";

    if (
        type.includes("threat") ||
        type.includes("failed") ||
        type.includes("security")
    ) return "security";

    if (
        type.includes("file") ||
        type.includes("upload") ||
        type.includes("download") ||
        type.includes("share")
    ) return "file";

    return "other";
}

function formatDate(value) {
    if (!value) return "—";

    const date = new Date(value.replace(" ", "T") + "Z");

    if (Number.isNaN(date.getTime())) return value;

    return date.toLocaleString();
}

function createCell(value) {
    const cell = document.createElement("td");
    cell.textContent = value || "—";
    return cell;
}

function displayEvents() {
    const query = searchInput.value.toLowerCase().trim();
    const filter = eventFilter.value;

    const filteredEvents = allEvents.filter(event => {
        const category = classifyEvent(event.event_type);

        const matchesFilter = filter === "all" || category === filter;

        const searchable = [
            event.event_type,
            event.details,
            event.ip_address
        ].join(" ").toLowerCase();

        return matchesFilter && searchable.includes(query);
    });

    document.getElementById("totalEvents").textContent = allEvents.length;

    document.getElementById("securityEvents").textContent =
        allEvents.filter(event =>
            classifyEvent(event.event_type) === "security"
        ).length;

    document.getElementById("loginEvents").textContent =
        allEvents.filter(event =>
            classifyEvent(event.event_type) === "login"
        ).length;

    const totalPages = Math.max(1, Math.ceil(filteredEvents.length / PAGE_SIZE));

    currentPage = Math.min(currentPage, totalPages - 1);

    const start = currentPage * PAGE_SIZE;
    const visibleEvents = filteredEvents.slice(start, start + PAGE_SIZE);

    activityTable.replaceChildren();

    if (visibleEvents.length === 0) {
        const row = document.createElement("tr");
        const cell = createCell("No matching activity found.");
        cell.colSpan = 4;
        cell.className = "empty-state";
        row.appendChild(cell);
        activityTable.appendChild(row);
    }

    visibleEvents.forEach(event => {
        const row = document.createElement("tr");

        const eventCell = document.createElement("td");
        const badge = document.createElement("span");

        const category = classifyEvent(event.event_type);

        badge.className = `event-tag ${category}`;
        badge.textContent = event.event_type.replaceAll("_", " ");

        eventCell.appendChild(badge);

        row.append(
            eventCell,
            createCell(event.details),
            createCell(event.ip_address),
            createCell(formatDate(event.timestamp))
        );

        activityTable.appendChild(row);
    });

    document.getElementById("pageNumber").textContent =
        `Page ${currentPage + 1} of ${totalPages}`;

    previousButton.disabled = currentPage === 0;
    nextButton.disabled = currentPage >= totalPages - 1;
}

async function loadActivity() {
    activityMessage.className = "activity-message";
    activityTable.replaceChildren();

    const loadingRow = document.createElement("tr");
    const loadingCell = createCell("Loading activity...");
    loadingCell.colSpan = 4;
    loadingCell.className = "empty-state";
    loadingRow.appendChild(loadingCell);
    activityTable.appendChild(loadingRow);

    try {
        const response = await fetch(
            `/audit/events?limit=100&offset=0`
        );

        const data = await response.json();

        if (response.status === 401) {
            window.location.href = "/";
            return;
        }

        if (!response.ok) {
            throw new Error(data.error || "Unable to load activity.");
        }

        allEvents = data.events || [];
        currentPage = 0;
        displayEvents();

    } catch (error) {
        activityTable.replaceChildren();

        const row = document.createElement("tr");
        const cell = createCell(error.message);
        cell.colSpan = 4;
        cell.className = "empty-state";
        row.appendChild(cell);
        activityTable.appendChild(row);
    }
}

searchInput.addEventListener("input", () => {
    currentPage = 0;
    displayEvents();
});

eventFilter.addEventListener("change", () => {
    currentPage = 0;
    displayEvents();
});

previousButton.addEventListener("click", () => {
    if (currentPage > 0) {
        currentPage--;
        displayEvents();
    }
});

nextButton.addEventListener("click", () => {
    currentPage++;
    displayEvents();
});

document.getElementById("refreshActivity")
    .addEventListener("click", loadActivity);

loadActivity();
