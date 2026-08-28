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
| HTML Escaping
|--------------------------------------------------------------------------
*/

function escapeHtml(
    value
) {

    return String(
        value ?? ""
    )

        .replaceAll(
            "&",
            "&amp;"
        )

        .replaceAll(
            "<",
            "&lt;"
        )

        .replaceAll(
            ">",
            "&gt;"
        )

        .replaceAll(
            '"',
            "&quot;"
        )

        .replaceAll(
            "'",
            "&#039;"
        );
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


    /*
     * Reset previous results
     */

    clearResults();


    scanButton.disabled =
        true;


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

        scanButton.disabled =
            false;

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