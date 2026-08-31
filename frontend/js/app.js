const urlInput =
    document.getElementById(
        "applicationUrl"
    );

const authorizedInput =
    document.getElementById(
        "authorized"
    );

const scanButton =
    document.getElementById(
        "scanButton"
    );

const statusBox =
    document.getElementById(
        "status"
    );

const results =
    document.getElementById(
        "results"
    );


/*
|--------------------------------------------------------------------------
| Status
|--------------------------------------------------------------------------
*/

function setStatus(
    message,
    type = ""
) {
    statusBox.textContent = message;

    statusBox.className =
        `status ${type}`;
}


/*
|--------------------------------------------------------------------------
| Clear Results
|--------------------------------------------------------------------------
*/

function clearResults() {
    results.classList.add(
        "hidden"
    );
}


/*
|--------------------------------------------------------------------------
| Busy State
|--------------------------------------------------------------------------
*/

/*
 * Discovery and Mendix analysis both render into the same result
 * card, so only one of them may run at a time.
 */

let requestInFlight = false;


function setBusy(
    busy
) {
    requestInFlight = busy;

    scanButton.disabled = busy;

    mendixButton.disabled = busy;
}


/*
|--------------------------------------------------------------------------
| Display Discovery Results
|--------------------------------------------------------------------------
*/

function showResults(
    data
) {
    results.classList.remove(
        "hidden"
    );

    /*
     * V0.2 backend structure:
     *
     * data
     * └── application
     *     ├── id
     *     ├── platform
     *     ├── technologies
     *     └── attack_surface
     */

    const application =
        data.application;

    if (!application) {
        throw new Error(
            "The server returned an invalid application response."
        );
    }


    const attackSurface =
        application.attack_surface || {};

    const technologies =
        application.technologies || [];

    const endpoints =
        attackSurface.endpoints || [];

    const pages =
        attackSurface.pages || [];

    const links =
        attackSurface.links || [];

    const forms =
        attackSurface.forms || [];

    const scripts =
        attackSurface.scripts || [];

    const potentialApiPaths =
        attackSurface.potential_api_paths || [];


    /*
     |--------------------------------------------------------------------------
     | Application Information
     |--------------------------------------------------------------------------
     */

    document.getElementById(
        "finalUrl"
    ).textContent =
        application.final_url || "-";


    document.getElementById(
        "statusCode"
    ).textContent =
        `HTTP ${
            application.status_code ?? "-"
        }`;


    document.getElementById(
        "responseTime"
    ).textContent =
        `${
            application.response_time_ms ?? "-"
        } ms`;


    document.getElementById(
        "pagesScanned"
    ).textContent =
        attackSurface.pages_scanned ?? pages.length;


    document.getElementById(
        "endpointCount"
    ).textContent =
        endpoints.length;


    document.getElementById(
        "technologyCount"
    ).textContent =
        technologies.length;


    /*
     |--------------------------------------------------------------------------
     | Attack Surface Metrics
     |--------------------------------------------------------------------------
     */

    document.getElementById(
        "surfacePages"
    ).textContent =
        pages.length;


    document.getElementById(
        "surfaceLinks"
    ).textContent =
        links.length;


    document.getElementById(
        "surfaceForms"
    ).textContent =
        forms.length;


    document.getElementById(
        "surfaceScripts"
    ).textContent =
        scripts.length;


    document.getElementById(
        "surfaceApis"
    ).textContent =
        potentialApiPaths.length;


    /*
     |--------------------------------------------------------------------------
     | Technologies
     |--------------------------------------------------------------------------
     */

    const technologiesContainer =
        document.getElementById(
            "technologies"
        );


    if (!technologies.length) {

        technologiesContainer.innerHTML =
            `
            <p class="muted">
                No technologies confidently detected yet.
            </p>
            `;

    } else {

        technologiesContainer.innerHTML =
            technologies
                .map(
                    technology => `
                        <div class="tech">

                            <strong>
                                ${escapeHtml(
                                    technology.name
                                )}
                            </strong>

                            <small>
                                ${escapeHtml(
                                    technology.category
                                )}

                                ·

                                ${escapeHtml(
                                    technology.confidence
                                )}
                            </small>

                        </div>
                    `
                )
                .join("");

    }


    /*
     |--------------------------------------------------------------------------
     | Platform Detection
     |--------------------------------------------------------------------------
     */

    const platform =
        document.getElementById(
            "platform"
        );


    const detectedPlatform =
        application.platform ||
        "Unknown";


    if (
        detectedPlatform
            .toLowerCase()
            === "mendix"
    ) {

        platform.className =
            "platform detected";

        platform.innerHTML =
            `
            <strong>
                Mendix detected
            </strong>

            <br>

            <span>
                Deep Mendix analysis will be performed
                using the authorized Mendix model acquisition
                process in the next phase.
            </span>
            `;

    } else {

        platform.className =
            "platform";

        platform.innerHTML =
            `
            <strong>
                ${escapeHtml(
                    detectedPlatform
                )}
            </strong>

            <br>

            <span>
                Generic application analysis will be used.
            </span>
            `;

    }


    /*
     |--------------------------------------------------------------------------
     | Endpoints
     |--------------------------------------------------------------------------
     */

    const endpointContainer =
        document.getElementById(
            "endpoints"
        );


    if (!endpoints.length) {

        endpointContainer.innerHTML =
            `
            <p class="muted">
                No endpoints discovered yet.
            </p>
            `;

    } else {

        endpointContainer.innerHTML =
            endpoints
                .slice(0, 100)
                .map(
                    endpoint => `
                        <div class="endpoint">

                            <span class="method">
                                ${escapeHtml(
                                    endpoint.method
                                )}
                            </span>

                            ${escapeHtml(
                                endpoint.url
                            )}

                        </div>
                    `
                )
                .join("");

    }


    /*
     |--------------------------------------------------------------------------
     | Security Posture
     |--------------------------------------------------------------------------
     */

    showSecurity(
        application
    );


    /*
     |--------------------------------------------------------------------------
     | Store Application ID
     |--------------------------------------------------------------------------
     */

    if (application.id) {

        localStorage.setItem(
            "currentApplicationId",
            application.id
        );

        console.log(
            "Application ID:",
            application.id
        );

    }


    /*
     |--------------------------------------------------------------------------
     | Store Current Application
     |--------------------------------------------------------------------------
     */

    localStorage.setItem(
        "currentApplication",
        JSON.stringify(
            application
        )
    );
}


/*
|--------------------------------------------------------------------------
| Display Security Posture
|--------------------------------------------------------------------------
*/

function showSecurity(
    application
) {

    const security =
        application.security || {};

    const findings =
        security.findings || [];

    const recommendations =
        security.recommendations || [];


    document.getElementById(
        "riskScore"
    ).textContent =
        security.risk_score ?? 0;


    const grade =
        document.getElementById(
            "riskGrade"
        );

    grade.textContent =
        security.risk_grade || "-";

    grade.className =
        `risk-grade grade-${
            String(
                security.risk_grade || "a"
            ).toLowerCase()
        }`;


    document.getElementById(
        "totalFindings"
    ).textContent =
        security.total_findings ?? findings.length;


    document.getElementById(
        "rulesEvaluated"
    ).textContent =
        security.rules_evaluated ?? 0;


    document.getElementById(
        "severityCounts"
    ).innerHTML =
        severityCounts(
            security.severity_counts
        );


    const findingsLink =
        document.getElementById(
            "allFindingsLink"
        );

    findingsLink.href =
        `/findings.html?application=${
            encodeURIComponent(
                application.id || ""
            )
        }`;

    findingsLink.classList.toggle(
        "hidden",
        !findings.length
    );


    /*
     * Top findings
     */

    const findingsContainer =
        document.getElementById(
            "topFindings"
        );

    if (!findings.length) {

        findingsContainer.innerHTML =
            `
            <p class="muted">
                No security findings were raised by the
                ${escapeHtml(
                    security.rules_evaluated ?? 0
                )} rules that were evaluated.
            </p>
            `;

    } else {

        findingsContainer.innerHTML =
            findings
                .slice(0, 10)
                .map(
                    finding => `
                        <a
                            class="finding"
                            href="/finding-detail.html?application=${
                                encodeURIComponent(
                                    application.id || ""
                                )
                            }&finding=${
                                encodeURIComponent(
                                    finding.id || ""
                                )
                            }"
                        >

                            ${severityBadge(
                                finding.severity
                            )}

                            <div>

                                <strong>
                                    ${escapeHtml(
                                        finding.title
                                    )}
                                </strong>

                                <small>
                                    ${escapeHtml(
                                        finding.rule_id
                                    )}

                                    ·

                                    ${escapeHtml(
                                        finding.category
                                    )}

                                    ·

                                    risk ${escapeHtml(
                                        (finding.risk || {}).score ?? 0
                                    )}
                                </small>

                            </div>

                        </a>
                    `
                )
                .join("");

    }


    /*
     * Recommendations
     */

    const recommendationContainer =
        document.getElementById(
            "recommendations"
        );

    if (!recommendations.length) {

        recommendationContainer.innerHTML =
            `
            <p class="muted">
                No remediation actions required.
            </p>
            `;

    } else {

        recommendationContainer.innerHTML =
            recommendations
                .map(
                    recommendation => `
                        <div class="recommendation">

                            ${severityBadge(
                                recommendation.severity
                            )}

                            <div>

                                <strong>
                                    ${escapeHtml(
                                        recommendation.rule_id
                                    )}
                                </strong>

                                <p>
                                    ${escapeHtml(
                                        recommendation.recommendation
                                    )}
                                </p>

                                <small>
                                    ${escapeHtml(
                                        recommendation.category
                                    )}

                                    ·

                                    ${escapeHtml(
                                        recommendation.finding_count ?? 1
                                    )} finding(s)
                                </small>

                            </div>

                        </div>
                    `
                )
                .join("");

    }
}


/*
|--------------------------------------------------------------------------
| Start Discovery
|--------------------------------------------------------------------------
*/

async function startDiscovery() {

    const url =
        urlInput.value.trim();


    /*
     * Reset previous results
     */

    if (requestInFlight) {
        return;
    }


    clearResults();


    /*
     * Validate URL
     */

    if (!url) {

        setStatus(
            "Enter an application URL.",
            "error"
        );

        return;
    }


    /*
     * Validate authorization
     */

    if (!authorizedInput.checked) {

        setStatus(
            "Confirm that you are authorized to assess this application.",
            "error"
        );

        return;
    }


    setBusy(true);


    setStatus(
        "Discovering application...",
        "loading"
    );


    try {

        /*
         * Send discovery request
         */

        const response =
            await fetch(
                "/api/discover",
                {
                    method:
                        "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            url: url
                        })
                }
            );


        /*
         * Parse server response
         */

        const data =
            await response.json();


        /*
         * Handle backend errors
         */

        if (!response.ok) {

            throw new Error(
                data.error ||
                "Discovery failed."
            );

        }


        /*
         * Make sure the backend returned
         * an application
         */

        if (
            !data.application
        ) {

            throw new Error(
                "Discovery completed but no application data was returned."
            );

        }


        /*
         * Display results
         */

        showResults(
            data
        );


        /*
         * Success message
         */

        setStatus(
            `Discovery completed. Application ID: ${
                data.application_id || "unknown"
            }`,
            "success"
        );


    } catch (error) {

        console.error(
            "Discovery error:",
            error
        );


        setStatus(
            error.message ||
            "Discovery failed.",
            "error"
        );


    } finally {

        setBusy(false);

    }
}


/*
|--------------------------------------------------------------------------
| Mendix Model Analysis
|--------------------------------------------------------------------------
*/

const mendixInput =
    document.getElementById(
        "mendixModel"
    );

const mendixButton =
    document.getElementById(
        "mendixButton"
    );

const mendixStatusBox =
    document.getElementById(
        "mendixStatus"
    );


function setMendixStatus(
    message,
    type = ""
) {
    mendixStatusBox.textContent = message;

    mendixStatusBox.className =
        `status ${type}`;
}


async function analyzeMendixModel() {

    if (requestInFlight) {
        return;
    }


    clearResults();


    const file =
        (mendixInput.files || [])[0];


    if (!file) {

        setMendixStatus(
            "Select a Mendix model JSON file first.",
            "error"
        );

        return;
    }


    setMendixStatus(
        "Analyzing Mendix model...",
        "loading"
    );

    setBusy(true);


    try {

        const form = new FormData();

        form.append(
            "model",
            file
        );


        const response =
            await fetch(
                "/api/mendix/analyze",
                {
                    method: "POST",
                    body: form
                }
            );


        const data =
            await response.json();


        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Mendix model analysis failed."
            );

        }


        showResults(
            data
        );


        setMendixStatus(
            `Analysis completed. Application ID: ${
                data.application_id || "unknown"
            }`,
            "success"
        );


    } catch (error) {

        console.error(
            "Mendix analysis error:",
            error
        );

        setMendixStatus(
            error.message ||
            "Mendix model analysis failed.",
            "error"
        );


    } finally {

        setBusy(false);

    }
}


/*
|--------------------------------------------------------------------------
| Button Event
|--------------------------------------------------------------------------
*/

scanButton.addEventListener(
    "click",
    startDiscovery
);

mendixButton.addEventListener(
    "click",
    analyzeMendixModel
);


/*
|--------------------------------------------------------------------------
| Enter Key Support
|--------------------------------------------------------------------------
*/

urlInput.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Enter"
        ) {

            startDiscovery();

        }

    }
);