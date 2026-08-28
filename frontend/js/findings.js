const applicationId =
    currentApplicationId();

const findingsContainer =
    document.getElementById(
        "findings"
    );

const severityFilter =
    document.getElementById(
        "severityFilter"
    );

const categoryFilter =
    document.getElementById(
        "categoryFilter"
    );


/*
|--------------------------------------------------------------------------
| Rendering
|--------------------------------------------------------------------------
*/

function renderFindings(
    findings
) {

    document.getElementById(
        "findingCount"
    ).textContent =
        findings.length;


    if (!findings.length) {

        findingsContainer.innerHTML =
            `
            <p class="muted">
                No findings match the current filters.
            </p>
            `;

        return;
    }


    findingsContainer.innerHTML =
        findings
            .map(
                finding => `
                    <a
                        class="finding"
                        href="/finding-detail.html?application=${
                            encodeURIComponent(
                                applicationId
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

                                ${escapeHtml(
                                    finding.confidence
                                )}

                                ·

                                risk ${escapeHtml(
                                    (finding.risk || {}).score ?? 0
                                )}
                            </small>

                            <span class="location">
                                ${escapeHtml(
                                    finding.location
                                )}
                            </span>

                        </div>

                    </a>
                `
            )
            .join("");
}


function renderCategories(
    findings
) {

    const categories =
        [
            ...new Set(
                findings
                    .map(
                        finding => finding.category
                    )
                    .filter(Boolean)
            )
        ].sort();


    const selected =
        categoryFilter.value;


    categoryFilter.innerHTML =
        `<option value="">All</option>` +
        categories
            .map(
                category => `
                    <option value="${escapeHtml(category)}">
                        ${escapeHtml(category)}
                    </option>
                `
            )
            .join("");


    categoryFilter.value = selected;
}


/*
|--------------------------------------------------------------------------
| Loading
|--------------------------------------------------------------------------
*/

async function loadApplication() {

    const data =
        await getJson(
            `/api/applications/${
                encodeURIComponent(
                    applicationId
                )
            }`
        );

    const application =
        data.application || {};

    const security =
        application.security || {};


    document.getElementById(
        "applicationUrl"
    ).textContent =
        application.final_url || "-";


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
        "severityCounts"
    ).innerHTML =
        severityCounts(
            security.severity_counts
        );
}


async function loadFindings() {

    const parameters =
        new URLSearchParams();

    if (severityFilter.value) {

        parameters.set(
            "severity",
            severityFilter.value
        );

    }

    if (categoryFilter.value) {

        parameters.set(
            "category",
            categoryFilter.value
        );

    }


    const data =
        await getJson(
            `/api/applications/${
                encodeURIComponent(
                    applicationId
                )
            }/findings?${parameters.toString()}`
        );


    renderFindings(
        data.findings || []
    );
}


async function initialize() {

    if (!applicationId) {

        findingsContainer.innerHTML =
            `
            <p class="muted">
                No application selected. Run a discovery scan
                first, or pick one from the
                <a href="/dashboard.html">dashboard</a>.
            </p>
            `;

        return;
    }


    try {

        await loadApplication();

        const all =
            await getJson(
                `/api/applications/${
                    encodeURIComponent(
                        applicationId
                    )
                }/findings`
            );

        renderCategories(
            all.findings || []
        );

        renderFindings(
            all.findings || []
        );

    } catch (error) {

        findingsContainer.innerHTML =
            `
            <p class="status error">
                ${escapeHtml(
                    error.message
                )}
            </p>
            `;

    }
}


severityFilter.addEventListener(
    "change",
    loadFindings
);

categoryFilter.addEventListener(
    "change",
    loadFindings
);


initialize();
