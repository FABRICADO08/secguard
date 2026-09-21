/*
|--------------------------------------------------------------------------
| Findings list / group details
|--------------------------------------------------------------------------
| Without ?group= this is the full findings list for a system; with it the
| page drills into one group of the chosen grouping.
*/

const applicationId = currentApplicationId();

rememberApplication(applicationId);

const groupName = queryParameter("group") || "";

const grouping = GROUPINGS[queryParameter("grouping")]
    ? queryParameter("grouping")
    : "owasp";

const view = renderShell({
    scope: "system",
    active: "findings",
    applicationId,
    period: false,
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        {
            text: "Security",
            href: `/system-security.html?application=${
                encodeURIComponent(applicationId)
            }`,
        },
        { text: groupName || "All findings" },
    ],
});

const FILTER_KEYS = ["severity", "category", "platform"];


function filtersFromLocation() {
    const filters = {};

    FILTER_KEYS.forEach(key => {
        const value = queryParameter(key);

        if (value) {
            filters[key] = value;
        }
    });

    return filters;
}


function findingRow(finding) {
    const link =
        `/finding-detail.html?application=${
            encodeURIComponent(applicationId)
        }&finding=${encodeURIComponent(finding.id || "")}`;

    return `
        <tr class="row-${escapeHtml(finding.severity)}">

            <td data-label="Type">
                <a class="row-title" href="${link}">
                    ${escapeHtml(finding.title)}
                </a>
                <div class="row-meta">
                    Rule: ${escapeHtml(finding.rule_id)}
                    · Category: ${escapeHtml(finding.category)}
                </div>
                <div class="row-meta">
                    ${escapeHtml(finding.owasp || "Unclassified")}
                </div>
            </td>

            <td data-label="Location">
                <span class="mono">
                    ${escapeHtml(finding.location || "-")}
                </span>
            </td>

            <td data-label="Risk">${riskChip(finding)}</td>

            <td data-label="Finding age">
                ${escapeHtml(findingAge(finding.detected_at))}
            </td>

            <td data-label="Confidence">
                <span class="pill">
                    ${escapeHtml(finding.confidence || "-")}
                </span>
            </td>

            <td data-label="Platform">
                <span class="pill">
                    ${escapeHtml(finding.platform || "Generic")}
                </span>
            </td>

        </tr>
    `;
}


function optionsFor(findings, key, selected) {
    const values = [
        ...new Set(
            findings
                .map(finding => String(finding[key] || ""))
                .filter(Boolean)
        ),
    ].sort();

    return [
        `<option value="">All</option>`,
        ...values.map(
            value => `
                <option
                    value="${escapeHtml(value)}"
                    ${value === selected ? "selected" : ""}
                >${escapeHtml(titleCase(value))}</option>
            `
        ),
    ].join("");
}


function render(findings) {
    const filters = filtersFromLocation();

    const scoped = groupName
        ? findings.filter(
            finding => GROUPINGS[grouping].of(finding) === groupName
        )
        : findings;

    const visible = sortFindings(
        scoped.filter(finding =>
            FILTER_KEYS.every(
                key =>
                    !filters[key] ||
                    String(finding[key] || "").toLowerCase() ===
                        filters[key].toLowerCase()
            )
        )
    );

    view.innerHTML = `
        <section class="card">

            <div class="card__head">
                <h2>
                    ${escapeHtml(groupName || "All findings")}
                </h2>
                <div class="toolbar">
                    <div class="field">
                        <label for="severity">Severity</label>
                        <select id="severity" data-filter="severity">
                            ${optionsFor(
                                scoped,
                                "severity",
                                filters.severity
                            )}
                        </select>
                    </div>
                    <div class="field">
                        <label for="category">Category</label>
                        <select id="category" data-filter="category">
                            ${optionsFor(
                                scoped,
                                "category",
                                filters.category
                            )}
                        </select>
                    </div>
                    <div class="field">
                        <label for="platform">Platform</label>
                        <select id="platform" data-filter="platform">
                            ${optionsFor(
                                scoped,
                                "platform",
                                filters.platform
                            )}
                        </select>
                    </div>
                    <button class="chip" id="exportCsv" type="button">
                        Export as CSV
                    </button>
                </div>
            </div>

            <p class="muted">
                Showing ${visible.length} of ${scoped.length} finding(s).
            </p>

            <div class="table-wrap">
                <table class="data">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Location</th>
                            <th>Risk</th>
                            <th>Finding age</th>
                            <th>Confidence</th>
                            <th>Platform</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${visible.length
                            ? visible.map(findingRow).join("")
                            : `
                                <tr>
                                    <td colspan="6" class="empty">
                                        No finding matches these filters.
                                    </td>
                                </tr>
                            `}
                    </tbody>
                </table>
            </div>

        </section>
    `;

    view.querySelectorAll("[data-filter]").forEach(select => {
        select.addEventListener("change", () => {
            const parameters = new URLSearchParams(
                window.location.search
            );

            parameters.set("application", applicationId);

            if (select.value) {
                parameters.set(select.dataset.filter, select.value);
            } else {
                parameters.delete(select.dataset.filter);
            }

            window.location.search = parameters.toString();
        });
    });

    document
        .getElementById("exportCsv")
        .addEventListener("click", () =>
            downloadCsv(
                "secguard-findings.csv",
                [
                    [
                        "Rule",
                        "Title",
                        "Severity",
                        "Risk",
                        "Category",
                        "OWASP",
                        "CWE",
                        "Location",
                        "Confidence",
                        "Platform",
                        "Detected at",
                    ],
                    ...visible.map(finding => [
                        finding.rule_id,
                        finding.title,
                        finding.severity,
                        (finding.risk || {}).score,
                        finding.category,
                        finding.owasp,
                        finding.cwe,
                        finding.location,
                        finding.confidence,
                        finding.platform,
                        finding.detected_at,
                    ]),
                ]
            )
        );
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

    view.innerHTML = '<div class="card empty">Loading findings…</div>';

    try {
        const payload = await getJson(
            `/api/applications/${encodeURIComponent(
                applicationId
            )}/findings`
        );

        render(payload.findings || []);
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(error.message || "Could not load findings.")}
            </div>
        `;
    }
}


load();
