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

    <section class="card" id="teamsCard">
        <div class="card__head"><h2>Teams and business units</h2></div>
        <p class="muted">Loading…</p>
    </section>

    <section class="card" id="alertsCard">
        <div class="card__head"><h2>Alerts and digest</h2></div>
        <p class="muted">Loading…</p>
    </section>

    <section class="card" id="ticketsCard">
        <div class="card__head"><h2>Ticket sync</h2></div>
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


function teamFieldset(team, scanned, index) {
    const chosen = new Set(team.applications || []);
    const known = new Set(scanned.map(application => application.key));
    const applications = [
        ...scanned,
        ...[...chosen].filter(key => !known.has(key)).map(key => ({ key, name: `${key} (no scan yet)` })),
    ];

    return `
        <fieldset class="team-editor" data-team="${index}">
            <div class="objectives-form">
                <div class="field">
                    <label for="teamName${index}">Team</label>
                    <input id="teamName${index}" name="name" maxlength="80" value="${escapeHtml(team.name || "")}">
                </div>
                <div class="field">
                    <label for="teamUnit${index}">Business unit</label>
                    <input id="teamUnit${index}" name="business_unit" maxlength="80" value="${escapeHtml(team.business_unit || "")}">
                </div>
                <div class="field">
                    <label for="teamMembers${index}">Members (GitHub logins, comma separated)</label>
                    <input id="teamMembers${index}" name="members" value="${escapeHtml((team.members || []).join(", "))}">
                </div>
            </div>
            <div class="team-editor__apps">
                ${applications.length ? applications.map(application => `
                    <label>
                        <input type="checkbox" name="applications" value="${escapeHtml(application.key)}"
                            ${chosen.has(application.key) ? "checked" : ""}>
                        ${escapeHtml(application.name)}
                    </label>
                `).join("") : '<span class="muted">No scanned applications yet.</span>'}
            </div>
            <button class="button button--ghost" type="button" data-remove-team="${index}">Remove team</button>
        </fieldset>
    `;
}


function readTeams(form) {
    return [...form.querySelectorAll("[data-team]")].map(fieldset => ({
        name: fieldset.querySelector("[name=name]").value,
        business_unit: fieldset.querySelector("[name=business_unit]").value,
        members: fieldset.querySelector("[name=members]").value.split(",").map(login => login.trim()).filter(Boolean),
        applications: [...fieldset.querySelectorAll("[name=applications]:checked")].map(box => box.value),
    }));
}


function renderTeams(data) {
    const card = document.getElementById("teamsCard");

    const intro = `
        <div class="card__head"><h2>Teams and business units</h2></div>
        <p class="muted">
            Group applications by team and business unit. Members can read the
            results of their team's applications even without GitHub access to
            them; running scans and changing findings still need write access
            on GitHub.
        </p>
    `;

    if (!data.can_edit) {
        card.innerHTML = `${intro}${data.teams.length ? `
            <dl class="pairs">${data.teams.map(team => `
                <dt>${escapeHtml(team.name)}</dt>
                <dd>${escapeHtml(team.business_unit || "No business unit")} ·
                    ${team.applications.length} application${team.applications.length === 1 ? "" : "s"}</dd>
            `).join("")}</dl>` : '<p class="muted">No teams yet. An administrator can add them here.</p>'}`;
        return;
    }

    card.innerHTML = `
        ${intro}
        <form id="teamsForm">
            ${data.teams.map((team, index) => teamFieldset(team, data.applications, index)).join("")}
            <div class="toolbar">
                <button class="button button--ghost" type="button" id="addTeam">Add team</button>
                <button class="button" type="submit">Save teams</button>
                <span id="teamsStatus" class="muted" role="status"></span>
            </div>
        </form>
    `;

    const form = document.getElementById("teamsForm");

    document.getElementById("addTeam").addEventListener("click", () =>
        renderTeams({ ...data, teams: [...readTeams(form), { name: "", applications: [], members: [] }] }));

    form.addEventListener("click", event => {
        const button = event.target.closest("[data-remove-team]");

        if (button) {
            const teams = readTeams(form);
            teams.splice(Number(button.dataset.removeTeam), 1);
            renderTeams({ ...data, teams });
        }
    });

    form.addEventListener("submit", async event => {
        event.preventDefault();

        const status = document.getElementById("teamsStatus");

        status.textContent = "Saving…";

        try {
            const response = await apiFetch("/api/teams", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ teams: readTeams(form) }),
            });

            const saved = await response.json();

            if (!response.ok) {
                throw new Error(saved.error || "Could not save the teams.");
            }

            renderTeams(saved);
            document.getElementById("teamsStatus").textContent = "Saved.";
        } catch (error) {
            status.textContent = error.message;
        }
    });
}


getJson("/api/teams")
    .then(renderTeams)
    .catch(error => {
        document.getElementById("teamsCard").innerHTML = `
            <div class="card__head"><h2>Teams and business units</h2></div>
            <p class="muted">${escapeHtml(error.message)}</p>
        `;
    });


function ticketSummary(settings) {
    if (!settings.provider) {
        return `Not configured. Set <span class="mono">SECGUARD_TICKET_PROVIDER</span> to
            <span class="mono">github</span>, <span class="mono">jira</span> or
            <span class="mono">azure</span> on the server.`;
    }
    if (!settings.configured) {
        return `${escapeHtml(settings.label)}s need these server settings: ${settings.missing
            .map(name => `<span class="mono">${escapeHtml(name)}</span>`).join(", ")}.`;
    }
    const automatic = settings.min_severity === "none"
        ? "Tickets are opened from each finding's page."
        : `Every scan opens a ${escapeHtml(settings.label)} for each new ${
            escapeHtml(settings.min_severity)} or worse finding.`;
    return `${automatic} Accepting a risk or marking a false positive closes the ticket as not planned,
        and closing a ticket as not planned accepts the risk. A ticket closes when a scan no longer
        detects its finding and reopens if the finding is still there.
        ${settings.webhook ? "GitHub reports issue changes instantly through the webhook." : ""}`;
}


function renderTickets(settings) {
    const card = document.getElementById("ticketsCard");

    card.innerHTML = `
        <div class="card__head"><h2>Ticket sync</h2>${settings.configured
            ? '<span class="pill pill--met">Configured</span>' : ""}</div>
        <p class="muted">${ticketSummary(settings)}</p>
        ${settings.can_edit && settings.configured ? `
            <div class="toolbar">
                <button class="button button--ghost" id="syncTickets" type="button">Sync all applications now</button>
                <span id="ticketStatus" class="muted" role="status"></span>
            </div>` : ""}
    `;

    document.getElementById("syncTickets")?.addEventListener("click", async () => {
        const status = document.getElementById("ticketStatus");
        status.textContent = "Syncing…";
        try {
            const response = await apiFetch("/api/tickets/sync", { method: "POST" });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || "Sync failed.");
            }
            const result = data.result || {};
            status.textContent = `${result.opened || 0} opened · ${result.closed || 0} closed · ${
                result.reopened || 0} reopened · ${result.updated || 0} findings updated${
                result.errors ? ` · ${result.errors} failed` : ""}`;
        } catch (error) {
            status.textContent = error.message;
        }
    });
}


getJson("/api/tickets")
    .then(renderTickets)
    .catch(error => {
        document.getElementById("ticketsCard").innerHTML = `
            <div class="card__head"><h2>Ticket sync</h2></div>
            <p class="muted">${escapeHtml(error.message)}</p>
        `;
    });
