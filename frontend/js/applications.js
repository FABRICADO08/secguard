/*
|--------------------------------------------------------------------------
| My applications
|--------------------------------------------------------------------------
| Applications whose GitHub repository the signed-in user can read, each
| with its latest SecGuard scan. Other applications are never returned.
*/

let view = null;


function applicationRow(repository) {
    const scan = repository.latest_scan;

    const health = scan && scan.health ? scan.health.overall || {} : {};

    const title = scan
        ? `<a class="row-title" href="/application-health.html?application=${encodeURIComponent(scan.id)}">
               ${escapeHtml(systemName(repository.name))}
           </a>`
        : `<span class="row-title">${escapeHtml(systemName(repository.name))}</span>`;

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


function render(data) {
    const scanned = data.repositories.filter(item => item.latest_scan);

    view.innerHTML = `
        <div id="scanNotice"></div>

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
            : `<tr><td colspan="5" class="empty">${
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
        tools: userChipMarkup(me),
    });

    bindSignOut();

    if (me.github_enabled && !me.authenticated) {
        view.innerHTML = `
            <section class="card signin">
                <h2>Sign in to see your applications</h2>
                <p class="muted">
                    SecGuard shows scan results only for applications your
                    GitHub account can access.
                </p>
                <p>
                    <a class="button" href="/auth/github/login">
                        Sign in with GitHub
                    </a>
                </p>
            </section>
        `;

        return;
    }

    view.innerHTML = '<div class="card empty">Loading applications…</div>';

    try {
        render(await getJson("/api/repositories"));
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(error.message || "Could not load applications.")}
            </div>
        `;
    }
}


load();
