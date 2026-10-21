/*
|--------------------------------------------------------------------------
| Settings
|--------------------------------------------------------------------------
*/

const view = renderShell({
    scope: "portfolio",
    active: "settings",
    period: false,
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        { text: "Settings" },
    ],
});


view.innerHTML = `
    <section class="card">

        <div class="card__head"><h2>API token</h2></div>

        <p class="muted">
            Scanning, model upload and delete require the token the server
            was started with (<span class="mono">SECGUARD_API_TOKEN</span>).
            It is kept in this browser only and sent as
            <span class="mono">X-API-Key</span>.
        </p>

        <div class="field">
            <label for="token">Token</label>
            <input type="password" id="token" autocomplete="off">
        </div>

        <div class="toolbar">
            <button class="button" id="saveToken" type="button">
                Save token
            </button>
            <button class="button button--ghost" id="clearToken"
                type="button">
                Clear
            </button>
            <span id="tokenStatus" class="muted"></span>
        </div>

    </section>

    <section class="card" id="alertsCard">
        <div class="card__head"><h2>Alerts and digest</h2></div>
        <p class="muted">Loading…</p>
    </section>

    <section class="card">
        <div class="card__head"><h2>Service</h2></div>
        <dl class="pairs" id="health">
            <dt>Status</dt>
            <dd>Checking…</dd>
        </dl>
    </section>
`;

const tokenInput = document.getElementById("token");

const tokenStatus = document.getElementById("tokenStatus");

tokenInput.value = apiToken();

document.getElementById("saveToken").addEventListener("click", () => {
    localStorage.setItem(API_TOKEN_KEY, tokenInput.value.trim());

    tokenStatus.textContent = "Token saved in this browser.";
});

document.getElementById("clearToken").addEventListener("click", () => {
    localStorage.removeItem(API_TOKEN_KEY);

    tokenInput.value = "";

    tokenStatus.textContent = "Token cleared.";
});


getJson("/api/health")
    .then(health => {
        document.getElementById("health").innerHTML = `
            <dt>Status</dt>
            <dd>${escapeHtml(health.status)}</dd>
            <dt>Service</dt>
            <dd>${escapeHtml(health.service)}</dd>
            <dt>Version</dt>
            <dd>${escapeHtml(health.version)}</dd>
        `;
    })
    .catch(error => {
        document.getElementById("health").innerHTML = `
            <dt>Status</dt>
            <dd>${escapeHtml(error.message || "Unreachable")}</dd>
        `;
    });


const CHANNEL_LABELS = { slack: "Slack", teams: "Microsoft Teams", email: "Email" };


async function postAlertAction(url, status) {
    status.textContent = "Sending…";

    try {
        const response = await apiFetch(url, { method: "POST" });

        const data = await response.json();

        if (!response.ok && !data.results) {
            throw new Error(data.error || "Request failed.");
        }

        status.textContent = Object.entries(data.results)
            .map(([channel, result]) => `${CHANNEL_LABELS[channel] || channel}: ${result}`)
            .join(" · ");
    } catch (error) {
        status.textContent = error.message;
    }
}


function renderAlerts(settings) {
    const card = document.getElementById("alertsCard");

    const channels = Object.entries(settings.channels)
        .map(([channel, enabled]) => `
            <dt>${escapeHtml(CHANNEL_LABELS[channel] || channel)}</dt>
            <dd>${enabled
                ? '<span class="pill pill--met">Configured</span>'
                : '<span class="muted">Not configured</span>'}</dd>
        `)
        .join("");

    const anyChannel = Object.values(settings.channels).some(Boolean);

    card.innerHTML = `
        <div class="card__head"><h2>Alerts and digest</h2></div>
        <p class="muted">
            A scan that adds a ${escapeHtml(settings.min_severity)} finding
            ${settings.min_severity === "critical" ? "" : "or worse "}sends an alert
            to every configured channel. Channels are set on the server with
            <span class="mono">SECGUARD_SLACK_WEBHOOK_URL</span>,
            <span class="mono">SECGUARD_TEAMS_WEBHOOK_URL</span> and the
            <span class="mono">SECGUARD_SMTP_*</span> settings.
        </p>
        <dl class="pairs">${channels}</dl>
        ${settings.can_edit && anyChannel ? `
            <div class="toolbar">
                <button class="button button--ghost" id="testAlert" type="button">Send test alert</button>
                <button class="button button--ghost" id="sendDigest" type="button">Send weekly digest now</button>
                <span id="alertStatus" class="muted" role="status"></span>
            </div>` : ""}
    `;

    const status = document.getElementById("alertStatus");

    document.getElementById("testAlert")?.addEventListener("click", () =>
        postAlertAction("/api/alerts/test", status));

    document.getElementById("sendDigest")?.addEventListener("click", () =>
        postAlertAction("/api/reports/digest", status));
}


getJson("/api/alerts")
    .then(renderAlerts)
    .catch(error => {
        document.getElementById("alertsCard").innerHTML = `
            <div class="card__head"><h2>Alerts and digest</h2></div>
            <p class="muted">${escapeHtml(error.message)}</p>
        `;
    });
