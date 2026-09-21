/*
|--------------------------------------------------------------------------
| System overview
|--------------------------------------------------------------------------
*/

const applicationId = currentApplicationId();

rememberApplication(applicationId);

const view = renderShell({
    scope: "system",
    active: "overview",
    applicationId,
    period: false,
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        { text: "System Overview" },
    ],
});


function metric(label, value) {
    return `
        <div>
            <div class="kpi__value">${escapeHtml(value)}</div>
            <div class="kpi__label">${escapeHtml(label)}</div>
        </div>
    `;
}


function technologyList(technologies) {
    if (!technologies.length) {
        return '<p class="muted">No technology confidently detected.</p>';
    }

    return technologies
        .map(
            technology => `
                <div>
                    <strong>${escapeHtml(technology.name)}</strong>
                    <span class="muted">
                        · ${escapeHtml(technology.category)}
                        · ${escapeHtml(technology.confidence)}
                    </span>
                </div>
            `
        )
        .join("");
}


function historyRows(system) {
    if (!system || system.history.length < 2) {
        return `
            <tr>
                <td colspan="3" class="empty">
                    Only one scan recorded for this system.
                </td>
            </tr>
        `;
    }

    return [...system.history]
        .reverse()
        .map(
            entry => `
                <tr>
                    <td data-label="Scan">
                        <a href="/system-security.html?application=${
                            encodeURIComponent(entry.id)
                        }">${escapeHtml(formatDateTime(entry.scan_date))}</a>
                    </td>
                    <td data-label="Risk score">
                        ${escapeHtml(entry.risk_score)}
                    </td>
                    <td data-label="Findings">
                        ${escapeHtml(entry.total_findings)}
                    </td>
                </tr>
            `
        )
        .join("");
}


function render(application, statistics, system) {
    const surface = application.attack_surface || {};

    const security = application.security || {};

    const partial = application.status === "certificate_rejected";

    view.innerHTML = `
        ${partial
            ? `<div class="notice notice--warning">
                    Only the TLS findings were recorded: the certificate of
                    ${escapeHtml(application.final_url)} was rejected, so no
                    HTTP response was ever observed.
                </div>`
            : ""}

        <section class="card">

            <div class="card__head">
                <h2>${escapeHtml(application.name)}</h2>
                <div class="toolbar">
                    <span class="pill">
                        ${escapeHtml(application.platform)}
                    </span>
                    <a
                        class="chip"
                        href="/system-security.html?application=${
                            encodeURIComponent(application.id)
                        }"
                    >Security</a>
                    <button
                        class="button button--danger"
                        id="deleteSystem"
                        type="button"
                    >Delete system</button>
                </div>
            </div>

            <dl class="pairs">
                <dt>Requested URL</dt>
                <dd class="mono">
                    ${escapeHtml(application.requested_url)}
                </dd>

                <dt>Final URL</dt>
                <dd class="mono">${escapeHtml(application.final_url)}</dd>

                <dt>Status</dt>
                <dd>${escapeHtml(application.status)}</dd>

                <dt>First scan</dt>
                <dd>${escapeHtml(formatDateTime(application.created_at))}</dd>

                <dt>Last update</dt>
                <dd>${escapeHtml(formatDateTime(application.updated_at))}</dd>
            </dl>

        </section>

        <section class="card">
            <div class="card__head"><h2>Scan result</h2></div>
            <div class="kpi">
                ${metric(
                    "HTTP status",
                    application.status_code ?? "-"
                )}
                ${metric(
                    "Response time",
                    application.response_time_ms != null
                        ? `${application.response_time_ms} ms`
                        : "-"
                )}
                ${metric("Findings", security.total_findings ?? 0)}
                ${metric("Rules evaluated", security.rules_evaluated ?? 0)}
                ${metric("Risk score", security.risk_score ?? 0)}
                ${metric("Grade", security.risk_grade || "-")}
            </div>
        </section>

        <div class="grid-two">

            <section class="card">
                <div class="card__head"><h2>Attack surface</h2></div>
                <div class="kpi">
                    ${metric("Pages", (surface.pages || []).length)}
                    ${metric("Forms", (surface.forms || []).length)}
                    ${metric("Scripts", (surface.scripts || []).length)}
                    ${metric("Endpoints", (surface.endpoints || []).length)}
                </div>
                <p style="margin-bottom:0">
                    <a href="/attack-surface.html?application=${
                        encodeURIComponent(application.id)
                    }">Inspect the attack surface</a>
                </p>
            </section>

            <section class="card">
                <div class="card__head"><h2>Technologies</h2></div>
                ${technologyList(application.technologies || [])}
            </section>

        </div>

        ${Object.keys(statistics || {}).length
            ? `<section class="card">
                    <div class="card__head"><h2>Model statistics</h2></div>
                    <div class="kpi">
                        ${Object.entries(statistics)
                            .map(([name, value]) =>
                                metric(titleCase(name.replace(/_/g, " ")),
                                    value)
                            )
                            .join("")}
                    </div>
                </section>`
            : ""}

        <section class="card">
            <div class="card__head"><h2>Scan history</h2></div>
            <div class="table-wrap">
                <table class="data">
                    <thead>
                        <tr>
                            <th>Scan</th>
                            <th>Risk score</th>
                            <th>Findings</th>
                        </tr>
                    </thead>
                    <tbody>${historyRows(system)}</tbody>
                </table>
            </div>
        </section>
    `;

    document
        .getElementById("deleteSystem")
        .addEventListener("click", async event => {
            if (!window.confirm("Delete this system and its findings?")) {
                return;
            }

            event.target.disabled = true;

            try {
                const response = await apiFetch(
                    `/api/applications/${encodeURIComponent(
                        application.id
                    )}`,
                    { method: "DELETE" }
                );

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || "Delete failed.");
                }

                localStorage.removeItem("currentApplicationId");

                window.location.href = "/dashboard.html";
            } catch (error) {
                event.target.disabled = false;

                window.alert(error.message || "Delete failed.");
            }
        });
}


async function load() {
    if (!applicationId) {
        view.innerHTML = `
            <div class="notice notice--warning">
                No application selected.
                <a href="/dashboard.html">Pick one from the portfolio</a>.
            </div>
        `;

        return;
    }

    view.innerHTML = '<div class="card empty">Loading system…</div>';

    try {
        const [details, summary] = await Promise.all([
            getJson(
                `/api/applications/${encodeURIComponent(applicationId)}`
            ),
            getJson("/api/portfolio/summary"),
        ]);

        render(
            details.application,
            details.model_statistics,
            summary.systems.find(system =>
                system.history.some(entry => entry.id === applicationId)
            )
        );
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(error.message || "Could not load the system.")}
            </div>
        `;
    }
}


load();
