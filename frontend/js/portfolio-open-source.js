/*
|--------------------------------------------------------------------------
| Portfolio open-source health
|--------------------------------------------------------------------------
| Every third-party library across the latest scan of each system: which
| systems ship it, at which versions, and with which advisories, version
| lag and licence.
*/

const view = renderShell({
    scope: "portfolio",
    active: "opensource",
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        { text: "Open Source Health" },
    ],
});


const LIBRARY_FILTERS = {
    all: ["All libraries", () => true],
    vulnerable: ["With known vulnerabilities", library => library.advisories.length > 0],
    outdated: ["Major versions behind", library => library.major_behind > 0],
    licence: ["Licence risk", library => library.license_risk],
};


let overview = null;


function healthLink(systemId) {
    return `/application-health.html?application=${encodeURIComponent(systemId)}`;
}


function kpi(title, value, label, span) {
    return `
        <section class="card ${span}">
            <p class="card__title">${escapeHtml(title)}</p>
            <div class="kpi">
                <div>
                    <div class="kpi__value">${Number(value) || 0}</div>
                    <div class="kpi__label">${escapeHtml(label)}</div>
                </div>
            </div>
        </section>
    `;
}


function advisoryMarkup(advisory) {
    return `
        <div>
            <span class="chip-count ${escapeHtml(advisory.severity)}">
                ${SEVERITY_INITIAL[advisory.severity] || ""}
            </span>
            <span class="mono">${escapeHtml(advisory.id)}</span>
            ${advisory.minimum_fix
                ? `<span class="muted">fixed in ${escapeHtml(advisory.minimum_fix)}</span>`
                : ""}
        </div>
    `;
}


function usageMarkup(usage) {
    const lag = usage.behind.major
        ? ` · ${Number(usage.behind.major)} major behind`
        : "";

    return `
        <div>
            <a href="${escapeHtml(healthLink(usage.system_id))}">${escapeHtml(usage.system)}</a>
            <span class="row-meta mono">
                ${escapeHtml(usage.version || "-")}
                · ${usage.direct ? "direct" : "transitive"}${escapeHtml(lag)}
            </span>
        </div>
    `;
}


function libraryRow(library) {
    return `
        <tr class="row-${escapeHtml(library.severity || "low")}">
            <td data-label="Library">
                <div>
                    <span class="row-title">${escapeHtml(library.name)}</span>
                    <div class="row-meta">${escapeHtml(library.ecosystem)}</div>
                </div>
            </td>
            <td data-label="Systems">
                <div class="usage-list">${library.usages.map(usageMarkup).join("")}</div>
            </td>
            <td data-label="Advisories">
                ${library.advisories.length
                    ? library.advisories.map(advisoryMarkup).join("")
                    : '<span class="muted">None known</span>'}
            </td>
            <td data-label="Latest"><span class="mono version">${escapeHtml(library.latest || "-")}</span></td>
            <td data-label="Licence">
                <div>
                    ${escapeHtml(library.license || "-")}
                    <div class="row-meta">
                        ${escapeHtml(library.license_category)}
                        ${library.license_risk ? '<span class="pill">licence risk</span>' : ""}
                    </div>
                </div>
            </td>
        </tr>
    `;
}


function systemRow(system) {
    return `
        <tr class="row-${escapeHtml(system.severity || "low")}">
            <td data-label="System">
                <a class="row-title" href="${escapeHtml(healthLink(system.id))}">
                    ${escapeHtml(system.name)}
                </a>
                <div class="row-meta">${escapeHtml(formatDate(system.scan_date))}</div>
            </td>
            <td data-label="Rating">
                ${system.rating === null || system.rating === undefined
                    ? '<span class="muted">-</span>'
                    : ratingMarkup(system.rating)}
            </td>
            <td data-label="Libraries">
                ${Number(system.dependencies)}
                <div class="row-meta">${Number(system.direct)} direct</div>
            </td>
            <td data-label="Vulnerable">${Number(system.vulnerable)}</td>
            <td data-label="Major behind">${Number(system.major_behind)}</td>
            <td data-label="Licence risk">${Number(system.license_risk)}</td>
            <td data-label="Libyears">
                ${system.libyears === null || system.libyears === undefined
                    ? "-"
                    : escapeHtml(Number(system.libyears).toFixed(1))}
            </td>
        </tr>
    `;
}


function tableMarkup(headers, bodyId) {
    return `
        <div class="table-wrap">
            <table class="data">
                <thead><tr>${headers.map(
                    header => `<th>${escapeHtml(header)}</th>`
                ).join("")}</tr></thead>
                <tbody id="${bodyId}"></tbody>
            </table>
        </div>
    `;
}


function libraryCsvRows(libraries) {
    return [
        ["Library", "Ecosystem", "System", "Version", "Direct", "Advisories", "Latest", "Licence", "Licence category"],
        ...libraries.flatMap(library => library.usages.map(usage => [
            library.name,
            library.ecosystem,
            usage.system,
            usage.version,
            usage.direct ? "yes" : "no",
            usage.advisories.join(" "),
            library.latest,
            library.license,
            library.license_category,
        ])),
    ];
}


function matchingLibraries() {
    const term = document.getElementById("librarySearch").value.trim().toLowerCase();
    const filter = LIBRARY_FILTERS[document.getElementById("libraryFilter").value] || LIBRARY_FILTERS.all;

    return overview.libraries.filter(library =>
        filter[1](library) && (
            !term ||
            library.name.toLowerCase().includes(term) ||
            library.advisories.some(advisory => advisory.id.toLowerCase().includes(term))
        )
    );
}


function paintLibraries() {
    const matching = matchingLibraries();

    document.getElementById("libraryRows").innerHTML = matching.length
        ? matching.map(libraryRow).join("")
        : '<tr><td colspan="5" class="empty">No library matches this search.</td></tr>';
}


function paintSystems() {
    const term = document.getElementById("systemSearch").value.trim().toLowerCase();
    const matching = overview.systems.filter(
        system => !term || system.name.toLowerCase().includes(term)
    );

    document.getElementById("systemRows").innerHTML = matching.length
        ? matching.map(systemRow).join("")
        : '<tr><td colspan="7" class="empty">No system matches this search.</td></tr>';
}


function librariesCard() {
    const options = Object.entries(LIBRARY_FILTERS).map(
        ([value, [label]]) => `<option value="${value}">${escapeHtml(label)}</option>`
    ).join("");

    return `
        <section class="card">
            <div class="card__head">
                <h2>Libraries</h2>
                <div class="toolbar">
                    <input
                        type="search"
                        id="librarySearch"
                        placeholder="Search by library or advisory"
                        aria-label="Search by library or advisory"
                    >
                    <select id="libraryFilter" aria-label="Filter libraries">${options}</select>
                    <button class="chip" id="exportLibraries" type="button">Export as CSV</button>
                </div>
            </div>
            <p class="card__subtitle">
                Where is a library used, and at which version? Libraries with
                known vulnerabilities are listed first.
            </p>
            ${tableMarkup(["Library", "Systems", "Advisories", "Latest", "Licence"], "libraryRows")}
        </section>
    `;
}


function render() {
    const totals = overview.totals;

    view.innerHTML = `
        <div class="kpi-grid">
            ${kpi("Libraries", totals.libraries, `in ${totals.systems} systems`, "span-3")}
            ${kpi("Vulnerable", totals.vulnerable, "libraries with advisories", "span-3")}
            ${kpi("Outdated", totals.major_behind, "major versions behind", "span-3")}
            ${kpi("Licence risk", totals.license_risk, "copyleft or non-commercial", "span-3")}
        </div>

        ${librariesCard()}

        <section class="card">
            ${systemsCardHeader("")}
            ${tableMarkup(
                ["System", "Open source rating", "Libraries", "Vulnerable", "Major behind", "Licence risk", "Libyears"],
                "systemRows"
            )}
        </section>
    `;

    document.getElementById("librarySearch").addEventListener("input", paintLibraries);
    document.getElementById("libraryFilter").addEventListener("change", paintLibraries);
    document.getElementById("systemSearch").addEventListener("input", paintSystems);

    wireCsvExport(
        "exportLibraries",
        "secguard-open-source.csv",
        () => libraryCsvRows(matchingLibraries())
    );

    paintLibraries();
    paintSystems();
}


async function load() {
    showLoading(view, "open-source health");

    try {
        overview = await getJson("/api/portfolio/open-source");

        if (!overview.systems.length) {
            view.innerHTML = portfolioEmptyState();

            return;
        }

        render();
    } catch (error) {
        renderLoadError(view, error, "Could not load open-source health.");
    }
}


load();
