/*
|--------------------------------------------------------------------------
| My applications
|--------------------------------------------------------------------------
| Applications whose GitHub repository the signed-in user can read, each
| with its latest SecGuard scan. Other applications are never returned.
*/

let view = null;


const OBJECTIVE_FIELDS = [
    "max_critical",
    "max_high",
    "min_maintainability",
    "min_health",
];


function objectiveValue(value) {
    return value === null || value === undefined ? "" : String(value);
}


function objectivesCell(scan) {
    const status = scan && scan.objectives;

    if (!status || status.met === null) {
        return '<span class="muted">-</span>';
    }

    if (status.met) {
        return '<span class="pill pill--met">Met</span>';
    }

    const missed = status.results.filter(result => result.met === false);

    const detail = missed
        .map(result => `${result.label} ${result.target} (now ${result.actual})`)
        .join("; ");

    return `<span class="pill pill--missed" title="${escapeHtml(detail)}">
        Missed ${missed.length}
    </span>`;
}


function objectivesCard(settings, repositories) {
    const scanned = repositories.filter(
        item => item.latest_scan && item.latest_scan.objectives
            && item.latest_scan.objectives.met !== null
    );

    const meeting = scanned.filter(item => item.latest_scan.objectives.met);

    const active = OBJECTIVE_FIELDS.filter(
        name => settings.objectives[name] !== null
            && settings.objectives[name] !== undefined
    );

    const list = active.length
        ? active.map(name => `
            <span class="pill">
                ${escapeHtml(settings.catalogue[name].label)}
                ${escapeHtml(objectiveValue(settings.objectives[name]))}
            </span>
        `).join(" ")
        : '<span class="muted">No objectives set.</span>';

    const form = settings.can_edit
        ? `
            <form id="objectivesForm" class="objectives-form">
                ${OBJECTIVE_FIELDS.map(name => {
                    const entry = settings.catalogue[name];

                    return `
                        <div class="field">
                            <label for="objective-${name}">${escapeHtml(entry.label)}</label>
                            <input
                                type="number"
                                id="objective-${name}"
                                name="${name}"
                                min="${entry.min}"
                                max="${entry.max}"
                                step="${entry.kind === "stars" ? "0.1" : "1"}"
                                placeholder="Off"
                                value="${escapeHtml(objectiveValue(settings.objectives[name]))}"
                            >
                        </div>
                    `;
                }).join("")}
                <div class="toolbar">
                    <button class="button" type="submit">Save objectives</button>
                </div>
            </form>
            <div id="objectivesNotice"></div>
        `
        : "";

    return `
        <section class="card">
            <div class="card__head"><h2>Objectives</h2></div>
            <p class="card__subtitle">
                ${meeting.length} of ${scanned.length} scanned applications
                meet every objective.
            </p>
            <div class="objective-list">${list}</div>
            ${form}
        </section>
    `;
}


function bindObjectivesForm() {
    const form = document.getElementById("objectivesForm");

    if (!form) {
        return;
    }

    form.addEventListener("submit", async event => {
        event.preventDefault();

        const notice = document.getElementById("objectivesNotice");

        const payload = Object.fromEntries(
            OBJECTIVE_FIELDS.map(name => {
                const value = form.elements[name].value.trim();

                return [name, value === "" ? null : Number(value)];
            })
        );

        try {
            const response = await apiFetch("/api/objectives", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Could not save the objectives.");
            }

            render(await getJson("/api/repositories"), data);
        } catch (error) {
            notice.innerHTML = `
                <div class="notice notice--error">${escapeHtml(error.message)}</div>
            `;
        }
    });
}


function applicationRow(repository) {
    const scan = repository.latest_scan;

    const health = scan && scan.health ? scan.health.overall || {} : {};

    const label = repository.display_name || systemName(repository.name);

    const title = scan
        ? `<a class="row-title" href="/application-health.html?application=${encodeURIComponent(scan.id)}">
               ${escapeHtml(label)}
           </a>`
        : `<span class="row-title">${escapeHtml(label)}</span>`;

    return `
        <tr>
            <td data-label="Application">
                <div>
                    ${title}
                    <div class="row-meta">
                        ${repository.private === null
                            ? ""
                            : repository.private ? "Private" : "Public"}
                        ${repository.description
                            ? ` · ${escapeHtml(repository.description)}`
                            : ""}
                    </div>
                </div>
            </td>

            <td data-label="Health">
                <span class="user-chip">
                    ${gradeBadge(health.grade, true)}
                    ${health.score !== undefined
                        ? `<span>${Number(health.score)}/100</span>`
                        : ""}
                </span>
            </td>

            <td data-label="Maintainability">
                ${scan && scan.maintainability !== null && scan.maintainability !== undefined
                    ? ratingMarkup(scan.maintainability)
                    : '<span class="muted">-</span>'}
            </td>

            <td data-label="Objectives">
                ${objectivesCell(scan)}
            </td>

            <td data-label="Findings">
                ${scan
                    ? severityChips(scan.severity_counts)
                    : '<span class="muted">Not scanned yet</span>'}
            </td>

            <td data-label="Last scan">
                ${escapeHtml(scan ? formatDateTime(scan.updated_at) : "-")}
            </td>

            <td data-label="Actions">
                ${repository.can_trigger
                    ? `<button
                           class="button button--ghost"
                           type="button"
                           data-scan="${escapeHtml(repository.name)}"
                       >Run scan</button>`
                    : ""}
            </td>
        </tr>
    `;
}


function render(data, settings) {
    const scanned = data.repositories.filter(item => item.latest_scan);

    view.innerHTML = `
        <div id="scanNotice"></div>

        ${objectivesCard(settings, data.repositories)}

        <section class="card">

            <div class="card__head">
                <h2>Applications (${data.repositories.length})</h2>
                <div class="toolbar">
                    <input
                        type="search"
                        id="applicationSearch"
                        placeholder="Search applications"
                        aria-label="Search applications"
                    >
                    <a class="button button--ghost" href="/api/reports/portfolio.pdf">
                        Portfolio PDF
                    </a>
                </div>
            </div>

            <p class="card__subtitle">
                ${scanned.length} of ${data.repositories.length} scanned.
                Scans run daily at 06:00 UTC; use Run scan to start one now.
            </p>

            <div class="table-wrap">
                <table class="data">
                    <thead>
                        <tr>
                            <th>Application</th>
                            <th>Health</th>
                            <th>Maintainability</th>
                            <th>Objectives</th>
                            <th>Findings</th>
                            <th>Last scan</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody id="applicationRows"></tbody>
                </table>
            </div>

        </section>
    `;

    const rows = document.getElementById("applicationRows");
    const search = document.getElementById("applicationSearch");

    const paint = () => {
        const term = search.value.trim().toLowerCase();

        const matching = data.repositories.filter(
            item => !term || String(item.name).toLowerCase().includes(term)
        );

        rows.innerHTML = matching.length
            ? matching.map(applicationRow).join("")
            : `<tr><td colspan="7" class="empty">${
                data.repositories.length
                    ? "No application matches this search."
                    : "No application scans yet."
            }</td></tr>`;
    };

    search.addEventListener("input", paint);

    rows.addEventListener("click", async event => {
        const button = event.target.closest("[data-scan]");

        if (!button) {
            return;
        }

        const notice = document.getElementById("scanNotice");

        button.disabled = true;

        try {
            const result = await triggerRepositoryScan(button.dataset.scan);

            notice.innerHTML = `
                <div class="notice notice--success">
                    Scan started for ${escapeHtml(button.dataset.scan)}.
                    Results appear here when the workflow finishes.
                    <a href="${escapeHtml(result.actions_url)}" target="_blank" rel="noopener">
                        Follow it on GitHub
                    </a>
                </div>
            `;
        } catch (error) {
            button.disabled = false;

            notice.innerHTML = `
                <div class="notice notice--error">
                    ${escapeHtml(error.message)}
                </div>
            `;
        }
    });

    bindObjectivesForm();

    paint();
}


async function load() {
    const me = await currentUser();

    view = renderShell({
        scope: "portfolio",
        active: "applications",
        period: false,
        breadcrumbs: [
            { text: "Portfolio", href: "/dashboard.html" },
            { text: "My Applications" },
        ],
    });

    if (me.github_enabled && !me.authenticated) {
        view.innerHTML = `
            <section class="card signin">
                <h2>Sign in to see your applications</h2>
                <p class="muted">
                    SecGuard shows scan results only for applications your
                    GitHub account can access.
                </p>
                <p>
                    <a class="button" href="${escapeHtml(signInUrl())}">
                        Sign in with GitHub
                    </a>
                </p>
            </section>
        `;

        return;
    }

    view.innerHTML = '<div class="card empty">Loading applications…</div>';

    try {
        const [data, settings] = await Promise.all([
            getJson("/api/repositories"),
            getJson("/api/objectives"),
        ]);

        render(data, settings);
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(error.message || "Could not load applications.")}
            </div>
        `;
    }
}


load();
