/*
|--------------------------------------------------------------------------
| Attack surface
|--------------------------------------------------------------------------
| Everything discovery collected about the reachable surface of a system.
*/

const applicationId = currentApplicationId();

rememberApplication(applicationId);

const view = renderShell({
    scope: "system",
    active: "surface",
    applicationId,
    period: false,
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        {
            text: "System",
            href: `/application.html?application=${
                encodeURIComponent(applicationId)
            }`,
        },
        { text: "Attack Surface" },
    ],
});


function list(items, format) {
    if (!items.length) {
        return '<p class="muted">Nothing discovered.</p>';
    }

    return `
        <div class="table-wrap">
            <table class="data">
                <tbody>
                    ${items
                        .slice(0, 200)
                        .map(item => `<tr><td>${format(item)}</td></tr>`)
                        .join("")}
                </tbody>
            </table>
        </div>
        ${items.length > 200
            ? `<p class="muted">
                    Showing the first 200 of ${items.length}.
                </p>`
            : ""}
    `;
}


function panel(title, body) {
    return `
        <section class="card">
            <div class="card__head"><h2>${escapeHtml(title)}</h2></div>
            ${body}
        </section>
    `;
}


function render(application) {
    const surface = application.attack_surface || {};

    const pages = surface.pages || [];
    const forms = surface.forms || [];
    const scripts = surface.scripts || [];
    const endpoints = surface.endpoints || [];
    const exposed = surface.exposed_paths || [];
    const libraries = surface.libraries || [];

    view.innerHTML = `
        <section class="card">
            <div class="card__head">
                <h2>${escapeHtml(application.name)}</h2>
                <span class="pill">
                    ${escapeHtml(application.platform)}
                </span>
            </div>
            <div class="kpi">
                <div>
                    <div class="kpi__value">${pages.length}</div>
                    <div class="kpi__label">Pages</div>
                </div>
                <div>
                    <div class="kpi__value">${forms.length}</div>
                    <div class="kpi__label">Forms</div>
                </div>
                <div>
                    <div class="kpi__value">${scripts.length}</div>
                    <div class="kpi__label">Scripts</div>
                </div>
                <div>
                    <div class="kpi__value">${endpoints.length}</div>
                    <div class="kpi__label">Endpoints</div>
                </div>
                <div>
                    <div class="kpi__value">${exposed.length}</div>
                    <div class="kpi__label">Exposed paths</div>
                </div>
            </div>
        </section>

        <div class="grid-two">

            ${panel(
                "Pages",
                list(
                    pages,
                    page => `<span class="mono">${escapeHtml(
                        page.url || page
                    )}</span>`
                )
            )}

            ${panel(
                "Endpoints",
                list(
                    endpoints,
                    endpoint => `
                        <span class="pill">
                            ${escapeHtml(endpoint.method || "GET")}
                        </span>
                        <span class="mono">
                            ${escapeHtml(endpoint.url || endpoint)}
                        </span>
                    `
                )
            )}

            ${panel(
                "Forms",
                list(
                    forms,
                    form => `
                        <span class="pill">
                            ${escapeHtml(form.method || "GET")}
                        </span>
                        <span class="mono">
                            ${escapeHtml(form.action || "-")}
                        </span>
                        <div class="row-meta">
                            ${escapeHtml(
                                (form.inputs || [])
                                    .map(input => input.name || input.type)
                                    .join(", ")
                            )}
                        </div>
                    `
                )
            )}

            ${panel(
                "Scripts",
                list(
                    scripts,
                    script => `<span class="mono">${escapeHtml(
                        script
                    )}</span>`
                )
            )}

            ${panel(
                "Exposed paths",
                list(
                    exposed,
                    path => `
                        <span class="mono">
                            ${escapeHtml(path.url || path)}
                        </span>
                        ${path.status_code
                            ? `<span class="pill">HTTP ${escapeHtml(
                                path.status_code
                            )}</span>`
                            : ""}
                    `
                )
            )}

            ${panel(
                "Disclosed libraries",
                list(
                    libraries,
                    library => `
                        <strong>${escapeHtml(library.name)}</strong>
                        <span class="pill">
                            ${escapeHtml(library.version || "unknown")}
                        </span>
                        <div class="row-meta mono">
                            ${escapeHtml(library.source || "")}
                        </div>
                    `
                )
            )}

        </div>
    `;
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

    view.innerHTML = '<div class="card empty">Loading attack surface…</div>';

    try {
        const payload = await getJson(
            `/api/applications/${encodeURIComponent(applicationId)}`
        );

        render(payload.application);
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(
                    error.message || "Could not load the attack surface."
                )}
            </div>
        `;
    }
}


load();
