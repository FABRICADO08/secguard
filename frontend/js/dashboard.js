/*
|--------------------------------------------------------------------------
| Portfolio overview
|--------------------------------------------------------------------------
*/

const view = renderShell({
    scope: "portfolio",
    active: "overview",
    period: false,
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        { text: "Overview" },
    ],
    tools: `
        <a class="button" href="/index.html">New scan</a>
    `,
});


function systemRow(system) {
    const link = `/system-security.html?application=${encodeURIComponent(
        system.id
    )}`;

    return `
        <tr class="row-${
            system.severity_counts.critical
                ? "critical"
                : system.severity_counts.high
                    ? "high"
                    : "low"
        }">

            <td data-label="System">
                <div>
                    <a class="row-title" href="${link}">
                        ${escapeHtml(system.name)}
                    </a>
                    <div class="row-meta mono">
                        ${escapeHtml(system.url || "")}
                    </div>
                </div>
            </td>

            <td data-label="Platform">
                <span class="pill">${escapeHtml(system.platform)}</span>
            </td>

            <td data-label="Last scan">
                ${escapeHtml(formatDate(system.scan_date))}
            </td>

            <td data-label="Rating">
                ${ratingMarkup(system.rating)}
            </td>

            <td data-label="Findings">
                <strong>${system.total_findings}</strong>
                ${deltaMarkup(
                    Object.values(system.severity_deltas || {}).reduce(
                        (sum, value) => sum + value,
                        0
                    )
                )}
            </td>

            <td data-label="Severity">
                ${severityChips(system.severity_counts)}
            </td>

            <td data-label="Actions">
                <button
                    class="button button--danger"
                    data-delete="${escapeHtml(system.id)}"
                    type="button"
                >
                    Delete
                </button>
            </td>

        </tr>
    `;
}


function render(summary) {
    const totals = summary.totals;

    const acute =
        totals.severity_counts.critical + totals.severity_counts.high;

    view.innerHTML = `
        <div class="kpi-grid">

            <section class="card span-3">
                <p class="card__title">Systems</p>
                <div class="kpi">
                    <div>
                        <div class="kpi__value">${totals.systems}</div>
                        <div class="kpi__label">analyzed</div>
                    </div>
                </div>
            </section>

            <section class="card span-3">
                <p class="card__title">Findings</p>
                <div class="kpi">
                    <div>
                        <div class="kpi__value">${totals.findings}</div>
                        <div class="kpi__label">open</div>
                    </div>
                </div>
            </section>

            <section class="card span-3">
                <p class="card__title">Critical + High</p>
                <div class="kpi">
                    <div>
                        <div class="kpi__value">${acute}</div>
                        <div class="kpi__label">need attention</div>
                    </div>
                </div>
            </section>

            <section class="card span-3">
                <p class="card__title">Portfolio rating</p>
                <div class="kpi">
                    <div>
                        ${ratingMarkup(totals.rating)}
                        <div class="kpi__label">average of all systems</div>
                    </div>
                </div>
            </section>

        </div>

        <section class="card">

            <div class="card__head">
                <h2>Systems</h2>
                <div class="toolbar">
                    <input
                        type="search"
                        id="systemSearch"
                        placeholder="Search by system name"
                        aria-label="Search by system name"
                    >
                    <a class="chip" href="/portfolio-security.html">
                        Security view
                    </a>
                </div>
            </div>

            <div class="table-wrap">
                <table class="data">
                    <thead>
                        <tr>
                            <th>System</th>
                            <th>Platform</th>
                            <th>Last scan</th>
                            <th>Rating</th>
                            <th>Findings</th>
                            <th>Severity</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody id="systemRows"></tbody>
                </table>
            </div>

            <div id="systemEmpty" class="empty hidden"></div>

        </section>
    `;

    const rows = document.getElementById("systemRows");
    const search = document.getElementById("systemSearch");

    const paint = () => {
        const term = search.value.trim().toLowerCase();

        const matching = summary.systems.filter(
            system =>
                !term ||
                String(system.name).toLowerCase().includes(term) ||
                String(system.url || "").toLowerCase().includes(term)
        );

        rows.innerHTML = matching.length
            ? matching.map(systemRow).join("")
            : `
                <tr>
                    <td colspan="7" class="empty">
                        No system matches this search.
                    </td>
                </tr>
            `;
    };

    search.addEventListener("input", paint);

    rows.addEventListener("click", async event => {
        const button = event.target.closest("[data-delete]");

        if (!button) {
            return;
        }

        const identifier = button.dataset.delete;

        if (!window.confirm("Delete this system and its findings?")) {
            return;
        }

        button.disabled = true;

        try {
            const response = await apiFetch(
                `/api/applications/${encodeURIComponent(identifier)}`,
                { method: "DELETE" }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Delete failed.");
            }

            load();
        } catch (error) {
            button.disabled = false;

            window.alert(error.message || "Delete failed.");
        }
    });

    paint();
}


async function load() {
    view.innerHTML = '<div class="card empty">Loading portfolio…</div>';

    try {
        const summary = await getJson("/api/portfolio/summary");

        if (!summary.systems.length) {
            view.innerHTML = `
                <section class="card empty">
                    <p>No system has been analyzed yet.</p>
                    <p><a class="button" href="/index.html">
                        Run the first scan
                    </a></p>
                </section>
            `;

            return;
        }

        render(summary);
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(error.message || "Could not load portfolio.")}
            </div>
        `;
    }
}


load();
