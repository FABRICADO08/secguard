/*
|--------------------------------------------------------------------------
| Finding detail
|--------------------------------------------------------------------------
*/

const applicationId = currentApplicationId();

const findingId = queryParameter("finding") || "";

const view = renderShell({
    scope: "system",
    active: "findings",
    applicationId,
    period: false,
    breadcrumbs: [
        { text: "Portfolio", href: "/dashboard.html" },
        {
            text: "Security",
            href: `/system-security.html?application=${
                encodeURIComponent(applicationId)
            }`,
        },
        {
            text: "Findings",
            href: `/findings.html?application=${
                encodeURIComponent(applicationId)
            }`,
        },
        { text: "Finding" },
    ],
});


function references(finding) {
    const links = finding.references || [];

    if (!links.length) {
        return '<span class="muted">None recorded.</span>';
    }

    return links
        .map(
            reference => `
                <div>
                    <a
                        href="${escapeHtml(reference)}"
                        rel="noreferrer noopener"
                        target="_blank"
                    >${escapeHtml(reference)}</a>
                </div>
            `
        )
        .join("");
}


function render(finding) {
    view.innerHTML = `
        <section class="card">

            <div class="card__head">
                <h2>${escapeHtml(finding.title)}</h2>
                ${riskChip(finding)}
            </div>

            <dl class="pairs">

                <dt>Rule</dt>
                <dd class="mono">${escapeHtml(finding.rule_id)}</dd>

                <dt>Severity</dt>
                <dd>${escapeHtml(titleCase(finding.severity))}</dd>

                <dt>Risk score</dt>
                <dd>${escapeHtml((finding.risk || {}).score ?? 0)} / 100</dd>

                <dt>Confidence</dt>
                <dd>${escapeHtml(titleCase(finding.confidence))}</dd>

                <dt>Category</dt>
                <dd>${escapeHtml(titleCase(finding.category))}</dd>

                <dt>Platform</dt>
                <dd>${escapeHtml(finding.platform || "Generic")}</dd>

                <dt>Location</dt>
                <dd class="mono">${escapeHtml(finding.location || "-")}</dd>

                <dt>Detected</dt>
                <dd>${escapeHtml(formatDateTime(finding.detected_at))}
                    (${escapeHtml(findingAge(finding.detected_at))})</dd>

                <dt>CWE</dt>
                <dd>${escapeHtml(finding.cwe || "-")}</dd>

                <dt>OWASP</dt>
                <dd>${escapeHtml(finding.owasp || "-")}</dd>

            </dl>

        </section>

        <div class="grid-two">

            <section class="card">
                <div class="card__head"><h2>Description</h2></div>
                <p>${escapeHtml(finding.description || "-")}</p>
            </section>

            <section class="card">
                <div class="card__head"><h2>Recommendation</h2></div>
                <p>${escapeHtml(finding.recommendation || "-")}</p>
                <div class="card__head" style="margin-top:14px">
                    <h2>References</h2>
                </div>
                ${references(finding)}
            </section>

        </div>

        <section class="card">
            <div class="card__head"><h2>Evidence</h2></div>
            <pre class="evidence">${escapeHtml(
                JSON.stringify(finding.evidence || {}, null, 2)
            )}</pre>
        </section>
    `;
}


async function load() {
    if (!applicationId || !findingId) {
        view.innerHTML = `
            <div class="notice notice--warning">
                No finding selected.
                <a href="/dashboard.html">Return to the portfolio</a>.
            </div>
        `;

        return;
    }

    view.innerHTML = '<div class="card empty">Loading finding…</div>';

    try {
        const payload = await getJson(
            `/api/applications/${encodeURIComponent(
                applicationId
            )}/findings/${encodeURIComponent(findingId)}`
        );

        render(payload.finding);
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(error.message || "Could not load the finding.")}
            </div>
        `;
    }
}


load();
