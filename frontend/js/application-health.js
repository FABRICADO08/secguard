/*
|--------------------------------------------------------------------------
| Application health
|--------------------------------------------------------------------------
| Latest application scan: health grades, vulnerable dependencies with the
| minimum fixing version, licences, freshness and code quality.
*/

const applicationId = currentApplicationId();

let view = null;


function aspectCard(title, aspect, caption) {
    const value = aspect || {};

    return `
        <section class="card span-3">
            <p class="card__title">${escapeHtml(title)}</p>
            <div class="kpi">
                ${gradeBadge(value.grade)}
                <div>
                    <div class="kpi__value">
                        ${value.score === undefined ? "-" : Number(value.score)}
                    </div>
                    ${value.stars === undefined ? "" : ratingMarkup(value.stars)}
                    <div class="kpi__label">${escapeHtml(caption)}</div>
                </div>
            </div>
        </section>
    `;
}


function percent(value) {
    return value === null || value === undefined
        ? "-"
        : `${Math.round(Number(value) * 100)}%`;
}


function worstSeverity(vulnerabilities) {
    return vulnerabilities
        .map(item => item.severity)
        .sort((left, right) => severityRank(left) - severityRank(right))[0] || "low";
}


function vulnerableRow(dependency) {
    const fix = dependency.remediation || {};

    const severity = worstSeverity(dependency.vulnerabilities);

    const upgrade = fix.target
        ? `<strong class="mono">${escapeHtml(fix.target)}</strong>
           ${fix.breaking ? '<span class="pill">major upgrade</span>' : ""}
           ${fix.breaking && fix.non_breaking_target
               ? `<div class="row-meta">Non-breaking: <span class="mono">${
                   escapeHtml(fix.non_breaking_target)}</span></div>`
               : ""}`
        : '<span class="muted">No fixed release</span>';

    return `
        <tr class="row-${escapeHtml(severity)}">
            <td data-label="Package">
                <div>
                    <span class="row-title">${escapeHtml(dependency.name)}</span>
                    <div class="row-meta mono">
                        ${escapeHtml(dependency.version || dependency.spec)}
                        · ${escapeHtml(dependency.manifest)}
                    </div>
                </div>
            </td>
            <td data-label="Advisories">
                ${dependency.vulnerabilities.map(item => `
                    <div>
                        <span class="chip-count ${escapeHtml(item.severity)}">
                            ${SEVERITY_INITIAL[item.severity] || ""}
                        </span>
                        <span class="mono">${escapeHtml(item.id)}</span>
                        <span class="muted">${escapeHtml(item.summary || "")}</span>
                    </div>
                `).join("")}
            </td>
            <td data-label="Minimum fix">${upgrade}</td>
            <td data-label="Reachability">
                <span class="pill">${escapeHtml(dependency.reachability || "unknown")}</span>
            </td>
        </tr>
    `;
}


function dependencyRow(dependency) {
    const freshness = dependency.freshness || {};

    const behind = freshness.behind
        ? freshness.behind.major
            ? `${freshness.behind.major} major`
            : freshness.behind.minor
                ? `${freshness.behind.minor} minor`
                : freshness.behind.patch
                    ? `${freshness.behind.patch} patch`
                    : "Up to date"
        : "-";

    return `
        <tr>
            <td data-label="Package">
                <div>
                    <span class="row-title">${escapeHtml(dependency.name)}</span>
                    <div class="row-meta">
                        ${escapeHtml(dependency.ecosystem)}
                        · ${dependency.direct ? "direct" : "transitive"}
                        · ${escapeHtml(dependency.scope)}
                    </div>
                </div>
            </td>
            <td data-label="Version" class="mono">
                ${escapeHtml(dependency.version || dependency.spec || "-")}
            </td>
            <td data-label="Latest" class="mono">
                ${escapeHtml(freshness.latest || "-")}
            </td>
            <td data-label="Behind">${escapeHtml(behind)}</td>
            <td data-label="Licence">
                ${escapeHtml(dependency.license_spdx || dependency.license || "-")}
                ${dependency.license_category
                    ? `<div class="row-meta">${escapeHtml(dependency.license_category)}</div>`
                    : ""}
            </td>
            <td data-label="Reachability">
                <span class="pill">${escapeHtml(dependency.reachability || "unknown")}</span>
            </td>
        </tr>
    `;
}


function hotspotRow(hotspot) {
    return `
        <tr>
            <td data-label="Function">
                <div>
                    <span class="row-title mono">${escapeHtml(hotspot.name)}</span>
                    <div class="row-meta mono">
                        ${escapeHtml(hotspot.path)}:${Number(hotspot.line)}
                    </div>
                </div>
            </td>
            <td data-label="Cyclomatic">${Number(hotspot.cyclomatic)}</td>
            <td data-label="Cognitive">${Number(hotspot.cognitive)}</td>
            <td data-label="Lines">${Number(hotspot.lines)}</td>
        </tr>
    `;
}


function table(headers, rows, empty) {
    return rows.length
        ? `
            <div class="table-wrap">
                <table class="data">
                    <thead><tr>${headers.map(
                        header => `<th>${escapeHtml(header)}</th>`
                    ).join("")}</tr></thead>
                    <tbody>${rows.join("")}</tbody>
                </table>
            </div>
        `
        : `<div class="empty">${escapeHtml(empty)}</div>`;
}


function render(application, access) {
    const report = application.repository || {};
    const meta = report.repository || {};
    const health = report.health || {};
    const statistics = report.statistics || {};
    const freshness = report.freshness || {};
    const licenses = report.licenses || {};
    const quality = report.quality || {};
    const metrics = quality.metrics || {};
    const dependencies = report.dependencies || [];

    const vulnerable = dependencies
        .filter(item => (item.vulnerabilities || []).length)
        .sort(
            (left, right) =>
                severityRank(worstSeverity(left.vulnerabilities)) -
                severityRank(worstSeverity(right.vulnerabilities))
        );

    const security = application.security || {};

    const sbom = format =>
        `/api/applications/${encodeURIComponent(applicationId)}/sbom?format=${format}`;

    view.innerHTML = `
        <div id="scanNotice"></div>

        <section class="card">
            <div class="card__head">
                <h2 id="applicationName">${escapeHtml(application.name || systemName(meta.name))}</h2>
                <form class="toolbar" id="renameForm" hidden>
                    <div class="field">
                        <input
                            type="text"
                            id="renameInput"
                            maxlength="80"
                            aria-label="Application name"
                            value="${escapeHtml(application.name || systemName(meta.name))}"
                        >
                    </div>
                    <button class="button" type="submit">Save</button>
                    <button class="button button--ghost" id="renameCancel" type="button">Cancel</button>
                </form>
                <div class="toolbar">
                    ${access.can_rename
                        ? '<button class="button button--ghost" id="renameStart" type="button">Rename</button>'
                        : ""}
                    ${access.can_trigger
                        ? '<button class="button" id="runScan" type="button">Run scan</button>'
                        : ""}
                    <a class="button button--ghost" href="${sbom("cyclonedx")}">
                        CycloneDX SBOM
                    </a>
                    <a class="button button--ghost" href="${sbom("spdx")}">
                        SPDX SBOM
                    </a>
                </div>
            </div>
            <dl class="pairs">
                <dt>Scanned</dt>
                <dd>${escapeHtml(formatDateTime(report.generated_at || application.updated_at))}</dd>
                <dt>Commit</dt>
                <dd class="mono">${escapeHtml((meta.commit || "-").slice(0, 12))}
                    ${meta.ref ? `· ${escapeHtml(meta.ref)}` : ""}</dd>
                <dt>Trigger</dt>
                <dd>${escapeHtml(meta.trigger || "-")}</dd>
                <dt>Project licence</dt>
                <dd>${escapeHtml(licenses.project || meta.license || "Not declared")}</dd>
            </dl>
        </section>

        <div class="kpi-grid">
            ${aspectCard("Overall health", health.overall, "weighted score")}
            ${aspectCard("Security", health.security, `${security.total_findings || 0} findings`)}
            ${aspectCard("Open source", health.open_source,
                `${statistics.dependencies || 0} dependencies`)}
            ${aspectCard("Maintainability", health.maintainability,
                `${(quality.findings || []).length} issues`)}
        </div>

        <section class="card">
            <div class="card__head">
                <h2>Vulnerable dependencies (${vulnerable.length})</h2>
                <a class="chip" href="/findings.html?application=${encodeURIComponent(applicationId)}">
                    All findings
                </a>
            </div>
            ${severityLegend(security.severity_counts || {})}
            ${table(
                ["Package", "Advisories", "Minimum fix", "Reachability"],
                vulnerable.map(vulnerableRow),
                "No known vulnerable dependency."
            )}
        </section>

        <div class="grid-two">
            <section class="card">
                <h2>Freshness</h2>
                <div class="metric-list">
                    <div><strong>${freshness.freshness_index ?? "-"}${
                        freshness.freshness_index === null || freshness.freshness_index === undefined ? "" : "%"
                    }</strong><span class="muted">freshness index</span></div>
                    <div><strong>${Number(freshness.major_behind || 0)}</strong>
                        <span class="muted">major versions behind</span></div>
                    <div><strong>${Number(freshness.minor_behind || 0)}</strong>
                        <span class="muted">minor versions behind</span></div>
                    <div><strong>${Number(freshness.libyears || 0)}</strong>
                        <span class="muted">libyears</span></div>
                </div>
            </section>

            <section class="card">
                <h2>Licences</h2>
                <div class="metric-list">
                    ${Object.entries(licenses.categories || {}).map(
                        ([category, count]) => `
                            <div><strong>${Number(count)}</strong>
                                <span class="muted">${escapeHtml(category)}</span></div>
                        `
                    ).join("") || '<div class="muted">No licence data.</div>'}
                </div>
            </section>
        </div>

        <section class="card">
            <h2>Code quality</h2>
            <div class="metric-list">
                <div><strong>${Number(metrics.code_lines || 0)}</strong>
                    <span class="muted">lines of code</span></div>
                <div><strong>${metrics.average_complexity ?? "-"}</strong>
                    <span class="muted">avg. complexity</span></div>
                <div><strong>${percent(metrics.duplication_ratio)}</strong>
                    <span class="muted">duplication</span></div>
                <div><strong>${percent(metrics.docstring_coverage)}</strong>
                    <span class="muted">docstring coverage</span></div>
                <div><strong>${percent(metrics.type_annotation_coverage)}</strong>
                    <span class="muted">type annotations</span></div>
                <div><strong>${Math.round(Number(metrics.technical_debt_minutes || 0) / 60)} h</strong>
                    <span class="muted">technical debt</span></div>
            </div>
            <h3>Complexity hotspots</h3>
            ${table(
                ["Function", "Cyclomatic", "Cognitive", "Lines"],
                (quality.hotspots || []).slice(0, 10).map(hotspotRow),
                "No complex functions."
            )}
        </section>

        <section class="card">
            <h2>Dependencies (${dependencies.length})</h2>
            ${table(
                ["Package", "Version", "Latest", "Behind", "Licence", "Reachability"],
                dependencies.map(dependencyRow),
                "No dependency manifests found."
            )}
        </section>
    `;

    bindRename(meta.name);

    const run = document.getElementById("runScan");

    if (run) {
        run.addEventListener("click", async () => {
            const notice = document.getElementById("scanNotice");

            run.disabled = true;

            try {
                const result = await triggerRepositoryScan(meta.name);

                notice.innerHTML = `
                    <div class="notice notice--success">
                        Scan started. Results appear when the workflow finishes.
                        <a href="${escapeHtml(result.actions_url)}" target="_blank" rel="noopener">
                            Follow it on GitHub
                        </a>
                    </div>
                `;
            } catch (error) {
                run.disabled = false;

                notice.innerHTML = `
                    <div class="notice notice--error">${escapeHtml(error.message)}</div>
                `;
            }
        });
    }
}


function bindRename(fullName) {
    const start = document.getElementById("renameStart");

    if (!start) {
        return;
    }

    const form = document.getElementById("renameForm");
    const heading = document.getElementById("applicationName");
    const input = document.getElementById("renameInput");

    const toggle = editing => {
        form.hidden = !editing;
        heading.hidden = editing;
        start.hidden = editing;

        if (editing) {
            input.focus();
        }
    };

    start.addEventListener("click", () => toggle(true));

    document.getElementById("renameCancel").addEventListener("click", () => toggle(false));

    form.addEventListener("submit", async event => {
        event.preventDefault();

        const notice = document.getElementById("scanNotice");

        try {
            const label = await renameApplication(fullName, input.value);

            heading.textContent = label;
            input.value = label;
            notice.innerHTML = "";
            toggle(false);
        } catch (error) {
            notice.innerHTML = `
                <div class="notice notice--error">${escapeHtml(error.message)}</div>
            `;
        }
    });
}


async function repositoryAccess(me, application) {
    const none = { can_trigger: false, can_rename: false };

    if (me.github_enabled && !me.authenticated) {
        return none;
    }

    const name = String(
        ((application.repository || {}).repository || {}).name || ""
    ).toLowerCase();

    try {
        const data = await getJson("/api/repositories");

        const item = (data.repositories || []).find(
            entry => String(entry.name).toLowerCase() === name
        );

        return item
            ? { can_trigger: Boolean(item.can_trigger), can_rename: Boolean(item.can_rename) }
            : none;
    } catch {
        return none;
    }
}


async function load() {
    const me = await currentUser();

    view = renderShell({
        scope: "system",
        active: "health",
        period: false,
        applicationId,
        breadcrumbs: [
            { text: "My Applications", href: "/applications.html" },
            { text: "Application Health" },
        ],
    });

    if (!applicationId) {
        view.innerHTML = `
            <div class="card empty">
                Pick an application from <a href="/applications.html">My Applications</a>.
            </div>
        `;

        return;
    }

    rememberApplication(applicationId);

    view.innerHTML = '<div class="card empty">Loading application…</div>';

    try {
        const data = await getJson(
            `/api/applications/${encodeURIComponent(applicationId)}`
        );

        if (data.application.platform !== "Repository") {
            window.location.replace(
                `/system-security.html?application=${encodeURIComponent(applicationId)}`
            );

            return;
        }

        render(data.application, await repositoryAccess(me, data.application));
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(error.message || "Could not load application.")}
                ${me.github_enabled && !me.authenticated
                    ? ` <a href="${escapeHtml(signInUrl())}">Sign in with GitHub</a>`
                    : ""}
            </div>
        `;
    }
}


load();
