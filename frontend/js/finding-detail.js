const detailApplicationId =
    currentApplicationId();

const findingId =
    queryParameter("finding") || "";

const detail =
    document.getElementById(
        "detail"
    );

const errorBox =
    document.getElementById(
        "error"
    );


function showError(
    message
) {

    errorBox.textContent = message;

    errorBox.className =
        "status error";
}


function setText(
    id,
    value
) {

    document.getElementById(
        id
    ).textContent =
        value || "-";
}


function render(
    finding
) {

    detail.classList.remove(
        "hidden"
    );


    document.getElementById(
        "backToFindings"
    ).href =
        `/findings.html?application=${
            encodeURIComponent(
                detailApplicationId
            )
        }`;


    setText(
        "findingTitle",
        finding.title
    );

    setText(
        "findingRule",
        finding.rule_id
    );

    setText(
        "findingLocation",
        finding.location
    );

    setText(
        "findingConfidence",
        finding.confidence
    );

    setText(
        "findingCategory",
        finding.category
    );

    setText(
        "findingPlatform",
        finding.platform
    );

    setText(
        "findingDescription",
        finding.description
    );

    setText(
        "findingRecommendation",
        finding.recommendation
    );

    setText(
        "findingCwe",
        finding.cwe
    );

    setText(
        "findingOwasp",
        finding.owasp
    );

    setText(
        "findingDetectedAt",
        finding.detected_at
    );

    setText(
        "findingRisk",
        (finding.risk || {}).score ?? 0
    );


    document.getElementById(
        "findingSeverity"
    ).innerHTML =
        severityBadge(
            finding.severity
        );


    document.getElementById(
        "findingEvidence"
    ).textContent =
        JSON.stringify(
            finding.evidence || {},
            null,
            2
        );
}


async function initialize() {

    if (!detailApplicationId || !findingId) {

        showError(
            "No finding selected."
        );

        return;
    }


    try {

        const data =
            await getJson(
                `/api/applications/${
                    encodeURIComponent(
                        detailApplicationId
                    )
                }/findings/${
                    encodeURIComponent(
                        findingId
                    )
                }`
            );

        render(
            data.finding || {}
        );

    } catch (error) {

        showError(
            error.message
        );

    }
}


initialize();
