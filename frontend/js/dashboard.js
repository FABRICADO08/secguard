const applicationsContainer =
    document.getElementById(
        "applications"
    );


function renderSummary(
    applications
) {

    const findingTotal =
        applications.reduce(
            (total, application) =>
                total + (application.total_findings || 0),
            0
        );

    const highestRisk =
        applications.reduce(
            (highest, application) =>
                Math.max(
                    highest,
                    application.risk_score || 0
                ),
            0
        );

    const criticalTotal =
        applications.reduce(
            (total, application) => {

                const counts =
                    application.severity_counts || {};

                return (
                    total +
                    (counts.critical || 0) +
                    (counts.high || 0)
                );
            },
            0
        );


    document.getElementById(
        "applicationCount"
    ).textContent =
        applications.length;

    document.getElementById(
        "findingTotal"
    ).textContent =
        findingTotal;

    document.getElementById(
        "highestRisk"
    ).textContent =
        highestRisk;

    document.getElementById(
        "criticalTotal"
    ).textContent =
        criticalTotal;
}


function renderApplications(
    applications
) {

    if (!applications.length) {

        applicationsContainer.innerHTML =
            `
            <p class="muted">
                No applications analyzed yet. Start a scan on the
                <a href="/index.html">discovery page</a>.
            </p>
            `;

        return;
    }


    applicationsContainer.innerHTML =
        applications
            .map(
                application => `
                  <div class="application-row">
                    <a
                        class="application"
                        href="/findings.html?application=${
                            encodeURIComponent(
                                application.id || ""
                            )
                        }"
                    >

                        <div class="risk-grade grade-${
                            String(
                                application.risk_grade || "a"
                            ).toLowerCase()
                        }">
                            ${escapeHtml(
                                application.risk_grade || "-"
                            )}
                        </div>

                        <div>

                            <strong>
                                ${escapeHtml(
                                    application.url ||
                                    application.name
                                )}
                            </strong>

                            <small>
                                ${escapeHtml(
                                    application.platform
                                )}

                                ·

                                risk ${escapeHtml(
                                    application.risk_score ?? 0
                                )}

                                ·

                                ${escapeHtml(
                                    application.total_findings ?? 0
                                )} findings

                                ·

                                ${escapeHtml(
                                    application.updated_at
                                )}
                            </small>

                            <div class="severity-counts">
                                ${severityCounts(
                                    application.severity_counts
                                )}
                            </div>

                        </div>

                    </a>

                    <button
                        class="danger"
                        type="button"
                        data-delete="${escapeHtml(
                            application.id || ""
                        )}"
                    >
                        Delete
                    </button>

                  </div>
                `
            )
            .join("");
}


async function deleteApplication(
    applicationId
) {

    const confirmed =
        window.confirm(
            "Delete this application and all of its findings?"
        );

    if (!confirmed) {
        return;
    }


    const response =
        await fetch(
            `/api/applications/${
                encodeURIComponent(
                    applicationId
                )
            }`,
            {
                method: "DELETE"
            }
        );


    const data =
        await response.json();


    if (!response.ok || !data.success) {

        window.alert(
            data.error ||
            "Could not delete the application."
        );

        return;
    }


    /*
     * Findings and detail pages remember the last application, so
     * a deleted one must not stay selected.
     */

    if (
        localStorage.getItem(
            "currentApplicationId"
        ) === applicationId
    ) {

        localStorage.removeItem(
            "currentApplicationId"
        );

    }


    await initialize();
}


async function initialize() {

    try {

        const data =
            await getJson(
                "/api/applications"
            );

        const applications =
            data.applications || [];

        renderSummary(
            applications
        );

        renderApplications(
            applications
        );

    } catch (error) {

        applicationsContainer.innerHTML =
            `
            <p class="status error">
                ${escapeHtml(
                    error.message
                )}
            </p>
            `;

    }
}


applicationsContainer.addEventListener(
    "click",
    event => {

        const button =
            event.target.closest(
                "[data-delete]"
            );

        if (!button) {
            return;
        }

        event.preventDefault();

        deleteApplication(
            button.dataset.delete
        );
    }
);


initialize();
