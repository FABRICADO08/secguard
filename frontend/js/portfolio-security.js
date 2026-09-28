/*
|--------------------------------------------------------------------------
| Portfolio security
|--------------------------------------------------------------------------
| Findings trend across the whole portfolio plus the per-system ranking.
*/

const view = renderShell({
    scope: "portfolio",
    active: "security",
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        { text: "Security" },
    ],
});


let summary = null;


function trendChart(trend) {
    const months = trend.slice(-periodMonths());

    return barChart(
        [
            {
                name: "New findings",
                color: "#1665d8",
                values: months.map(entry => entry.new),
            },
            {
                name: "Existing findings",
                color: "#a9c6f5",
                values: months.map(entry => entry.existing),
            },
            {
                name: "Resolved findings",
                color: "#2e9e5b",
                values: months.map(entry => entry.resolved),
            },
        ],
        months.map(entry => monthLabel(entry.month)),
        { title: "Findings per month" }
    );
}


function severityChart(counts) {
    return barChart(
        [
            {
                name: "Open findings",
                color: "#1665d8",
                values: ["critical", "high", "medium", "low"].map(
                    severity => counts[severity] || 0
                ),
            },
        ],
        ["Critical", "High", "Medium", "Low"],
        { title: "Open findings by severity" }
    );
}


function systemRow(system) {
    const link = `/system-security.html?application=${encodeURIComponent(
        system.id
    )}`;

    const counts = system.severity_counts;
    const deltas = system.severity_deltas;

    const cell = severity => `
        <td data-label="${titleCase(severity)}">
            ${counts[severity]}
            ${deltaMarkup(deltas[severity])}
        </td>
    `;

    return `
        <tr class="row-${
            counts.critical ? "critical" : counts.high ? "high" : "low"
        }">
            <td data-label="System">
                <a class="row-title" href="${link}">
                    ${escapeHtml(system.name)}
                </a>
            </td>
            <td data-label="Scan date">
                ${escapeHtml(formatDate(system.scan_date))}
            </td>
            <td data-label="Rating">${ratingMarkup(system.rating)}</td>
            <td data-label="Findings">
                <strong>${system.total_findings}</strong>
            </td>
            ${cell("critical")}
            ${cell("high")}
            ${cell("medium")}
            ${cell("low")}
        </tr>
    `;
}


function exportRows() {
    return [
        [
            "System",
            "URL",
            "Platform",
            "Scan date",
            "Rating",
            "Findings",
            "Critical",
            "High",
            "Medium",
            "Low",
        ],
        ...summary.systems.map(system => [
            system.name,
            system.url,
            system.platform,
            system.scan_date,
            system.rating,
            system.total_findings,
            system.severity_counts.critical,
            system.severity_counts.high,
            system.severity_counts.medium,
            system.severity_counts.low,
        ]),
    ];
}


function render() {
    const totals = summary.totals;

    view.innerHTML = `
        <section class="card">

            <div class="card__head">
                <h2>Findings trend</h2>
                <span class="muted">${escapeHtml(periodLabel())}</span>
            </div>

            <div class="grid-two">

                <div>
                    <p class="card__title">
                        Are you keeping pace with security findings?
                    </p>
                    <p class="card__subtitle">
                        New, existing and resolved findings for every scan
                        recorded in the month.
                    </p>
                    <div id="trendChart">${trendChart(summary.trend)}</div>
                </div>

                <div>
                    <p class="card__title">
                        Where does the risk sit today?
                    </p>
                    <p class="card__subtitle">
                        Open findings across the portfolio by severity.
                    </p>
                    ${severityChart(totals.severity_counts)}
                </div>

            </div>

        </section>

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
                    <button class="chip" id="exportCsv" type="button">
                        Export as CSV
                    </button>
                </div>
            </div>

            <div class="table-wrap">
                <table class="data">
                    <thead>
                        <tr>
                            <th>System</th>
                            <th>Scan date</th>
                            <th>Rating</th>
                            <th>Findings</th>
                            <th>Critical risk</th>
                            <th>High risk</th>
                            <th>Medium risk</th>
                            <th>Low risk</th>
                        </tr>
                    </thead>
                    <tbody id="systemRows"></tbody>
                </table>
            </div>

        </section>
    `;

    const rows = document.getElementById("systemRows");
    const search = document.getElementById("systemSearch");

    const paint = () => {
        const term = search.value.trim().toLowerCase();

        const matching = summary.systems.filter(
            system => !term ||
                String(system.name).toLowerCase().includes(term)
        );

        rows.innerHTML = matching.length
            ? matching.map(systemRow).join("")
            : `
                <tr>
                    <td colspan="8" class="empty">
                        No system matches this search.
                    </td>
                </tr>
            `;
    };

    search.addEventListener("input", paint);

    document
        .getElementById("exportCsv")
        .addEventListener("click", () =>
            downloadCsv("secguard-portfolio.csv", exportRows())
        );

    paint();
}


window.addEventListener("periodchange", () => {
    if (summary) {
        document.getElementById("trendChart").innerHTML = trendChart(
            summary.trend
        );
    }
});


async function load() {
    view.innerHTML = '<div class="card empty">Loading portfolio…</div>';

    try {
        summary = await getJson("/api/portfolio/summary");

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

        render();
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(error.message || "Could not load portfolio.")}
            </div>
        `;
    }
}


load();
