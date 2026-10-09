/*
|--------------------------------------------------------------------------
| System security
|--------------------------------------------------------------------------
| The per-system security dashboard: rating, severity mix, activity and
| the findings grouped the way the analyst chooses.
*/

const applicationId = currentApplicationId();

rememberApplication(applicationId);

const view = renderShell({
    scope: "system",
    active: "security",
    applicationId,
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        { text: "System", href: `/application.html?application=${
            encodeURIComponent(applicationId)
        }` },
        { text: "Security" },
    ],
});

const GROUPING_KEY = "secguardGrouping";


function currentGrouping() {
    const stored =
        queryParameter("grouping") ||
        localStorage.getItem(GROUPING_KEY);

    return GROUPINGS[stored] ? stored : "owasp";
}


function categoryChart(findings) {
    const counts = new Map();

    findings.forEach(finding => {
        const name = titleCase(finding.category || "other");

        counts.set(name, (counts.get(name) || 0) + 1);
    });

    const entries = [...counts.entries()].sort(
        (left, right) => right[1] - left[1]
    );

    if (!entries.length) {
        return '<div class="empty">No findings to chart.</div>';
    }

    return barChart(
        [
            {
                name: "Findings",
                color: "#1665d8",
                values: entries.map(entry => entry[1]),
            },
        ],
        entries.map(entry => entry[0]),
        { title: "Findings by category" }
    );
}


function groupRow(group, grouping) {
    const total = group.findings.length;

    const link =
        `/findings.html?application=${encodeURIComponent(applicationId)}` +
        `&grouping=${encodeURIComponent(grouping)}` +
        `&group=${encodeURIComponent(group.name)}`;

    return `
        <tr class="${total ? "row-high" : ""}">
            <td data-label="Description">
                ${total
                    ? `<a class="row-title" href="${link}">
                            ${escapeHtml(group.name)}
                        </a>`
                    : `<span class="row-title">
                            ${escapeHtml(group.name)}
                        </span>`}
            </td>
            <td data-label="Findings">
                ${severityChips(group.counts)}
            </td>
        </tr>
    `;
}


function render(application, findings, system) {
    const security = application.security || {};

    const counts = countBySeverity(findings);

    const current = Boolean(system) && system.id === application.id;

    /*
     * Every scan in a system's history carries its own comparison with
     * the scan before it, so an older scan shows its own activity.
     */
    const scan =
        (system &&
            system.history.find(entry => entry.id === application.id)) ||
        {};

    const deltas = scan.severity_deltas || {};

    const activity = scan.activity || {
        new: findings.length,
        existing: 0,
        resolved: 0,
    };

    const rating = current
        ? system.rating
        : ratingFromScore(security.risk_score);

    const grouping = currentGrouping();

    const groups = groupFindings(findings, grouping).filter(
        group => group.findings.length || GROUPINGS[grouping].all().length
    );

    view.innerHTML = `
        <div class="toolbar">
            <div class="field">
                <label for="grouping">Grouping</label>
                <select id="grouping">
                    ${Object.entries(GROUPINGS)
                        .map(
                            ([value, definition]) => `
                                <option
                                    value="${value}"
                                    ${value === grouping ? "selected" : ""}
                                >${escapeHtml(definition.label)}</option>
                            `
                        )
                        .join("")}
                </select>
            </div>
        </div>

        <div class="kpi-grid">

            <section class="card span-3">
                <div class="kpi">
                    <div>
                        <p class="card__title">Findings</p>
                        <div class="kpi__value">${findings.length}</div>
                        ${deltaMarkup(
                            Object.values(deltas).reduce(
                                (sum, value) => sum + value,
                                0
                            )
                        )}
                    </div>
                    <div>
                        <p class="card__title">
                            ${current ? "Latest scan" : "Selected scan"}
                        </p>
                        <div class="row-title">
                            ${escapeHtml(
                                formatDateTime(
                                    application.updated_at ||
                                    application.created_at
                                )
                            )}
                        </div>
                        <div class="kpi__label">
                            ${system ? system.scan_count : 1} scan(s) recorded
                        </div>
                    </div>
                </div>
            </section>

            <section class="card span-3">
                <p class="card__title">Security</p>
                <div style="text-align:center">
                    ${ratingMarkup(rating)}
                    <p class="card__subtitle">
                        Risk score ${escapeHtml(security.risk_score ?? 0)}/100
                        · grade ${escapeHtml(security.risk_grade || "-")}
                    </p>
                </div>
            </section>

            <section class="card span-3">
                <p class="card__title">Risk severity</p>
                ${severityBar(counts)}
                ${severityLegend(counts, deltas)}
            </section>

            <section class="card span-3">
                <p class="card__title">Activity</p>
                ${severityBar({
                    critical: activity.new,
                    high: 0,
                    medium: activity.existing,
                    low: activity.resolved,
                })}
                <div class="severity-legend">
                    <div class="border-critical">
                        <div class="count">${activity.new}</div>
                        <div class="name">New</div>
                    </div>
                    <div class="border-medium">
                        <div class="count">${activity.existing}</div>
                        <div class="name">Existing</div>
                    </div>
                    <div class="border-low">
                        <div class="count">${activity.resolved}</div>
                        <div class="name">Resolved</div>
                    </div>
                </div>
                <p class="card__subtitle">
                    Compared with the previous scan of this system.
                </p>
            </section>

            <section class="card span-12">
                <p class="card__title">Findings by category</p>
                ${categoryChart(findings)}
            </section>

        </div>

        <section class="card">

            <div class="card__head">
                <h2>${escapeHtml(GROUPINGS[grouping].label)}</h2>
                <div class="toolbar">
                    <a
                        class="chip"
                        href="/findings.html?application=${
                            encodeURIComponent(applicationId)
                        }"
                    >All findings</a>
                    ${csvExportButton()}
                </div>
            </div>

            <div class="table-wrap">
                <table class="data">
                    <thead>
                        <tr>
                            <th>Description</th>
                            <th>Findings</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${groups
                            .map(group => groupRow(group, grouping))
                            .join("")}
                    </tbody>
                </table>
            </div>

        </section>
    `;

    document
        .getElementById("grouping")
        .addEventListener("change", event => {
            localStorage.setItem(GROUPING_KEY, event.target.value);

            const parameters = new URLSearchParams(
                window.location.search
            );

            parameters.set("grouping", event.target.value);

            navigateWithParameters(parameters, applicationId);
        });

    wireCsvExport("exportCsv", "secguard-findings.csv", () =>
        findingsCsvRows(findings, [
            "rule", "title", "severity", "category", "owasp", "location",
            "detectedAt",
        ])
    );
}


async function load() {
    if (!requireApplication(view, applicationId)) {
        return;
    }

    showLoading(view, "system");

    try {
        const [details, findingsPayload, summary] = await Promise.all([
            getJson(
                `/api/applications/${encodeURIComponent(applicationId)}`
            ),
            getJson(
                `/api/applications/${encodeURIComponent(
                    applicationId
                )}/findings`
            ),
            getJson("/api/portfolio/summary"),
        ]);

        const system = summary.systems.find(entry =>
            entry.history.some(scan => scan.id === applicationId)
        );

        render(
            details.application,
            findingsPayload.findings || [],
            system
        );
    } catch (error) {
        renderLoadError(view, error, "Could not load the system.");
    }
}


load();
