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
