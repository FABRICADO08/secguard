/*
|--------------------------------------------------------------------------
| New scan
|--------------------------------------------------------------------------
| URL discovery plus the Mendix and OutSystems model uploads. All three
| produce an application record and hand over to the system views.
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
            <a class="chip" href="/settings.html">API token</a>
        </div>

        <div class="field">
            <label for="applicationUrl">Application URL</label>
            <input
                type="url"
                id="applicationUrl"
                placeholder="https://app.example.com"
                autocomplete="off"
            >
        </div>

        <label class="checkbox">
            <input type="checkbox" id="authorized">
            <span>
                I am authorized to assess this application.
            </span>
        </label>

        <div class="toolbar" style="margin-top:14px">
            <button class="button" id="scanButton" type="button">
                Start scan
            </button>
        </div>

        <div id="status" class="muted" style="margin-top:12px"></div>

    </section>

    <div class="grid-two">

        <section class="card">
            <div class="card__head"><h2>Analyze a Mendix model</h2></div>
            <div class="field">
                <label for="mendixModel">Model export (JSON)</label>
                <input type="file" id="mendixModel" accept=".json">
            </div>
            <button class="button button--ghost" id="mendixButton"
                type="button">
                Analyze Mendix model
            </button>
            <div id="mendixStatus" class="muted"
                style="margin-top:10px"></div>
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

    </div>

    <section class="card hidden" id="results"></section>
`;

const urlInput = document.getElementById("applicationUrl");
const authorizedInput = document.getElementById("authorized");
const scanButton = document.getElementById("scanButton");
const statusBox = document.getElementById("status");
const results = document.getElementById("results");

const mendixInput = document.getElementById("mendixModel");
const mendixButton = document.getElementById("mendixButton");
const mendixStatusBox = document.getElementById("mendixStatus");

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

    scanButton.disabled = busy;
    mendixButton.disabled = busy;
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
                    ${escapeHtml(application.platform)}
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


async function startDiscovery() {
    if (requestInFlight) {
        return;
    }

    clearResults();

    const url = urlInput.value.trim();

    if (!url) {
        setStatus(statusBox, "Enter an application URL.", "error");

        return;
    }

    if (!/^https?:\/\//i.test(url)) {
        setStatus(
            statusBox,
            "URL must start with http:// or https://.",
            "error"
        );

        return;
    }

    if (!authorizedInput.checked) {
        setStatus(
            statusBox,
            "Confirm that you are authorized to assess this application.",
            "error"
        );

        return;
    }

    setBusy(true);

    setStatus(statusBox, "Discovering application...");

    try {
        const response = await apiFetch("/api/discover", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Discovery failed.");
        }

        if (!data.application) {
            throw new Error(
                "Discovery completed but no application data was returned."
            );
        }

        showResults(data);

        if (data.partial) {
            setStatus(
                statusBox,
                `${
                    data.error || "The target could not be fetched."
                } Only the TLS findings were recorded. Application ID: ${
                    data.application_id || "unknown"
                }`,
                "warning"
            );
        } else {
            setStatus(
                statusBox,
                `Discovery completed. Application ID: ${
                    data.application_id || "unknown"
                }`,
                "success"
            );
        }
    } catch (error) {
        console.error("Discovery error:", error);

        setStatus(
            statusBox,
            error.message || "Discovery failed.",
            "error"
        );
    } finally {
        setBusy(false);
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


scanButton.addEventListener("click", startDiscovery);

urlInput.addEventListener("keydown", event => {
    if (event.key === "Enter") {
        startDiscovery();
    }
});

mendixButton.addEventListener("click", () =>
    analyzePlatformModel(
        "Mendix",
        "/api/mendix/analyze",
        mendixInput,
        mendixStatusBox
    )
);

outsystemsButton.addEventListener("click", () =>
    analyzePlatformModel(
        "OutSystems",
        "/api/outsystems/analyze",
        outsystemsInput,
        outsystemsStatusBox
    )
);
