/*
|--------------------------------------------------------------------------
| New scan
|--------------------------------------------------------------------------
| Starts a scan of an application through its GitHub repository's SecGuard
| workflow (Mendix projects in the repository included), plus the
| OutSystems model upload.
*/

const view = renderShell({
    scope: "portfolio",
    active: "scan",
    period: false,
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        { text: "New Scan" },
    ],
});


view.innerHTML = `
    <section class="card">

        <div class="card__head">
            <h2>Scan an application</h2>
        </div>

        <p class="card__subtitle">
            Each application is scanned from its GitHub repository,
            including the Mendix model when the repository holds a Mendix
            project. Scans run daily at 06:00 UTC; start one now from here.
        </p>

        <div id="githubScan"><div class="muted">Loading applications…</div></div>

        <div id="status" class="muted" style="margin-top:12px"></div>

    </section>

    <section class="card">
        <div class="card__head"><h2>Analyze an OutSystems model</h2></div>
        <div class="field">
            <label for="outsystemsModel">Model export (JSON)</label>
            <input type="file" id="outsystemsModel" accept=".json">
        </div>
        <button class="button button--ghost" id="outsystemsButton"
            type="button">
            Analyze OutSystems model
        </button>
        <div id="outsystemsStatus" class="muted"
            style="margin-top:10px"></div>
    </section>

    <section class="card hidden" id="results"></section>
`;

const githubScan = document.getElementById("githubScan");
const statusBox = document.getElementById("status");
const results = document.getElementById("results");

const outsystemsInput = document.getElementById("outsystemsModel");
const outsystemsButton = document.getElementById("outsystemsButton");
const outsystemsStatusBox = document.getElementById("outsystemsStatus");


function setStatus(box, message, type) {
    box.textContent = message;

    box.className = type ? `notice notice--${type}` : "muted";
}


function clearResults() {
    results.classList.add("hidden");

    results.innerHTML = "";
}


/*
 * Discovery and model analysis render into the same result card, so
 * only one of them may run at a time.
 */
let requestInFlight = false;


function setBusy(busy) {
    requestInFlight = busy;

    outsystemsButton.disabled = busy;
}


function showResults(data) {
    const application = data.application;

    if (!application) {
        throw new Error(
            "The server returned an invalid application response."
        );
    }

    rememberApplication(application.id);

    const security = application.security || {};

    const surface = application.attack_surface || {};

    const counts = security.severity_counts || {};

    results.classList.remove("hidden");

    results.innerHTML = `
        <div class="card__head">
            <h2>${escapeHtml(application.name)}</h2>
            <div class="toolbar">
                <span class="pill">
                    ${escapeHtml(platformLabel(application.platform))}
                </span>
                <a class="button" href="/system-security.html?application=${
                    encodeURIComponent(application.id || "")
                }">Open security view</a>
            </div>
        </div>

        <div class="kpi">
            <div>
                <div class="kpi__value">
                    ${escapeHtml(security.risk_score ?? 0)}
                </div>
                <div class="kpi__label">
                    Risk score (${escapeHtml(security.risk_grade || "-")})
                </div>
            </div>
            <div>
                <div class="kpi__value">
                    ${escapeHtml(
                        security.total_findings ??
                        (security.findings || []).length
                    )}
                </div>
                <div class="kpi__label">Findings</div>
            </div>
            <div>
                <div class="kpi__value">
                    ${escapeHtml(security.rules_evaluated ?? 0)}
                </div>
                <div class="kpi__label">Rules evaluated</div>
            </div>
            <div>
                <div class="kpi__value">
                    ${escapeHtml(application.status_code ?? "-")}
                </div>
                <div class="kpi__label">HTTP status</div>
            </div>
            <div>
                <div class="kpi__value">
                    ${escapeHtml((surface.pages || []).length)}
                </div>
                <div class="kpi__label">Pages</div>
            </div>
        </div>

        <div style="margin-top:14px">
            ${severityBar(counts)}
            ${severityLegend(counts)}
        </div>

        ${(security.findings || []).length
            ? `<div class="table-wrap" style="margin-top:16px">
                    <table class="data">
                        <thead>
                            <tr>
                                <th>Finding</th>
                                <th>Risk</th>
                                <th>Location</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${sortFindings(security.findings)
                                .slice(0, 10)
                                .map(
                                    finding => `
                                        <tr class="row-${escapeHtml(
                                            finding.severity
                                        )}">
                                            <td data-label="Finding">
                                                <a
                                                    class="row-title"
                                                    href="/finding-detail.html?application=${
                                                        encodeURIComponent(
                                                            application.id ||
                                                            ""
                                                        )
                                                    }&finding=${
                                                        encodeURIComponent(
                                                            finding.id || ""
                                                        )
                                                    }"
                                                >${escapeHtml(
                                                    finding.title
                                                )}</a>
                                                <div class="row-meta">
                                                    ${escapeHtml(
                                                        finding.rule_id
                                                    )}
                                                </div>
                                            </td>
                                            <td data-label="Risk">
                                                ${riskChip(finding)}
                                            </td>
                                            <td data-label="Location">
                                                <span class="mono">
                                                    ${escapeHtml(
                                                        finding.location || "-"
                                                    )}
                                                </span>
                                            </td>
                                        </tr>
                                    `
                                )
                                .join("")}
                        </tbody>
                    </table>
                </div>`
            : `<p class="muted" style="margin-top:16px">
                    No security findings were raised by the
                    ${escapeHtml(security.rules_evaluated ?? 0)} rules that
                    were evaluated.
                </p>`}

        ${(security.recommendations || []).length
            ? `<div style="margin-top:16px">
                    <h2 class="card__title" style="text-align:left">
                        Recommendations
                    </h2>
                    ${security.recommendations
                        .map(
                            recommendation => `
                                <p>
                                    <strong>${escapeHtml(
                                        recommendation.rule_id
                                    )}</strong>
                                    ${escapeHtml(
                                        recommendation.recommendation
                                    )}
                                    <span class="muted">
                                        (${escapeHtml(
                                            recommendation.finding_count ?? 1
                                        )} finding(s))
                                    </span>
                                </p>
                            `
                        )
                        .join("")}
                </div>`
            : ""}
    `;
}


function scannableOptions(repositories) {
    const scannable = repositories
        .filter(item => item.can_trigger)
        .map(item => ({
            name: item.name,
            label: item.display_name || systemName(item.name),
        }));

    const uses = {};

    scannable.forEach(item => {
        uses[item.label] = (uses[item.label] || 0) + 1;
    });

    return scannable
        .map(item => {
            const label = uses[item.label] > 1
                ? `${item.label} (${item.name})`
                : item.label;

            return `<option value="${escapeHtml(item.name)}">${escapeHtml(label)}</option>`;
        })
        .join("");
}


function renderGithubScan(me, data) {
    if (!me.github_enabled) {
        githubScan.innerHTML = `
            <div class="notice notice--warning">
                GitHub sign-in is not configured on this server, so scans
                start from each repository's SecGuard workflow on GitHub.
            </div>
        `;

        return;
    }

    if (!me.authenticated) {
        githubScan.innerHTML = `
            <p>
                <a class="button" href="${escapeHtml(signInUrl())}">
                    Sign in with GitHub
                </a>
            </p>
        `;

        return;
    }

    const options = scannableOptions(data.repositories);

    if (!options) {
        githubScan.innerHTML = `
            <div class="notice notice--warning">
                None of your applications can be scanned from your account.
                Starting a scan needs write access to the application's
                GitHub repository.
            </div>
        `;

        return;
    }

    githubScan.innerHTML = `
        <div class="field">
            <label for="applicationSelect">Application</label>
            <select id="applicationSelect">${options}</select>
        </div>
        <div class="toolbar" style="margin-top:14px">
            <button class="button" id="scanButton" type="button">
                Run scan
            </button>
        </div>
    `;

    document
        .getElementById("scanButton")
        .addEventListener("click", startRepositoryScan);
}


async function loadGithubScan() {
    const me = await currentUser();

    if (!me.unavailable && (!me.github_enabled || !me.authenticated)) {
        renderGithubScan(me, { repositories: [] });

        return;
    }

    try {
        const data = await getJson("/api/repositories");

        renderGithubScan(
            me.unavailable
                ? { github_enabled: data.github_enabled, authenticated: true }
                : me,
            data
        );
    } catch (error) {
        githubScan.innerHTML = "";

        setStatus(
            statusBox,
            error.message || "Could not load applications.",
            "error"
        );
    }
}


async function startRepositoryScan() {
    const select = document.getElementById("applicationSelect");
    const button = document.getElementById("scanButton");

    const label = select.options[select.selectedIndex].textContent;

    button.disabled = true;

    clearResults();

    setStatus(statusBox, `Starting a scan of ${label}...`);

    try {
        const result = await triggerRepositoryScan(select.value);

        statusBox.className = "notice notice--success";

        statusBox.innerHTML = `
            Scan started for ${escapeHtml(label)}. Results appear under
            My Applications when the workflow finishes.
            <a href="${escapeHtml(result.actions_url)}" target="_blank" rel="noopener">
                Follow it on GitHub
            </a>
        `;
    } catch (error) {
        setStatus(
            statusBox,
            error.message || "Could not start the scan.",
            "error"
        );
    } finally {
        button.disabled = false;
    }
}


async function analyzePlatformModel(platform, endpoint, input, box) {
    if (requestInFlight) {
        return;
    }

    clearResults();

    const file = (input.files || [])[0];

    if (!file) {
        setStatus(
            box,
            `Select a ${platform} model JSON file first.`,
            "error"
        );

        return;
    }

    setStatus(box, `Analyzing ${platform} model...`);

    setBusy(true);

    try {
        const form = new FormData();

        form.append("model", file);

        const response = await apiFetch(endpoint, {
            method: "POST",
            body: form,
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(
                data.error || `${platform} model analysis failed.`
            );
        }

        showResults(data);

        setStatus(
            box,
            `${platform} model analyzed. Application ID: ${
                data.application_id || "unknown"
            }`,
            "success"
        );
    } catch (error) {
        console.error(`${platform} analysis error:`, error);

        setStatus(
            box,
            error.message || `${platform} model analysis failed.`,
            "error"
        );
    } finally {
        setBusy(false);
    }
}


outsystemsButton.addEventListener("click", () =>
    analyzePlatformModel(
        "OutSystems",
        "/api/outsystems/analyze",
        outsystemsInput,
        outsystemsStatusBox
    )
);


loadGithubScan();
