/*
|--------------------------------------------------------------------------
| Finding detail
|--------------------------------------------------------------------------
*/

const applicationId = currentApplicationId();

const findingId = queryParameter("finding") || "";

const view = renderFindingPage(applicationId, [
    {
        text: "Findings",
        href: `/findings.html?application=${encodeURIComponent(applicationId)}`,
    },
    { text: "Finding" },
]);


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


function historyMarkup(history) {
    if (!history.length) {
        return '<p class="muted">No changes recorded yet.</p>';
    }

    return `<ul class="audit">${history
        .slice()
        .reverse()
        .map(entry => `
            <li>
                <strong>${escapeHtml(entry.by)}</strong>
                <span class="muted">${escapeHtml(formatDateTime(entry.at))}</span>
                <div>${Object.entries(entry.changes || {})
                    .map(([field, change]) => `${escapeHtml(titleCase(field))}: ${
                        escapeHtml(change.from || "-")} → ${escapeHtml(change.to || "-")}`)
                    .join("<br>")}</div>
            </li>
        `)
        .join("")}</ul>`;
}


function workflowCard(finding, canEdit) {
    const workflow = finding.workflow || {};
    const disabled = canEdit ? "" : "disabled";
    const options = Object.entries(WORKFLOW_STATUSES)
        .map(([value, label]) => `<option value="${value}" ${
            value === workflow.status ? "selected" : ""}>${escapeHtml(label)}</option>`)
        .join("");

    return `
        <section class="card">
            <div class="card__head"><h2>Remediation</h2>${workflowChip(finding)}</div>
            <form id="workflowForm" class="workflow-form">
                <div class="field">
                    <label for="workflowStatus">Status</label>
                    <select id="workflowStatus" name="status" ${disabled}>${options}</select>
                </div>
                <div class="field">
                    <label for="workflowOwner">Owner</label>
                    <input id="workflowOwner" name="owner" type="text" maxlength="100"
                        value="${escapeHtml(workflow.owner || "")}" ${disabled}>
                </div>
                <div class="field">
                    <label for="workflowDue">Due date</label>
                    <input id="workflowDue" name="due_date" type="date"
                        value="${escapeHtml(workflow.due_date || "")}" ${disabled}>
                </div>
                <div class="field workflow-form__reason">
                    <label for="workflowReason">Reason</label>
                    <textarea id="workflowReason" name="reason" maxlength="500" rows="2"
                        ${disabled}>${escapeHtml(workflow.reason || "")}</textarea>
                </div>
                <div>
                    ${canEdit
                        ? '<button class="button" type="submit">Save</button>'
                        : '<span class="muted">You need write access to change this.</span>'}
                    <span id="workflowMessage" role="status"></span>
                </div>
            </form>
            <p class="muted">Deadline by severity: ${
                escapeHtml(formatDate(workflow.sla_due_date) || "none")}</p>
            <div class="card__head"><h2>History</h2></div>
            ${historyMarkup(workflow.history || [])}
        </section>
    `;
}


function wireWorkflow(finding) {
    const form = document.getElementById("workflowForm");

    form.addEventListener("submit", async event => {
        event.preventDefault();
        const message = document.getElementById("workflowMessage");
        const response = await apiFetch(
            `/api/applications/${encodeURIComponent(applicationId)}/findings/${
                encodeURIComponent(findingId)}/workflow`,
            {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(Object.fromEntries(new FormData(form))),
            }
        );
        const data = await response.json();

        if (!response.ok) {
            message.className = "notice notice--error";
            message.textContent = data.error || "Could not save the change.";
            return;
        }

        render({ ...finding, workflow: data.workflow }, true);
        document.getElementById("workflowMessage").textContent = "Saved.";
    });
}


function render(finding, canEdit) {
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
                <dd>${escapeHtml(platformLabel(finding.platform))}</dd>

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

        ${workflowCard(finding, canEdit)}

        <section class="card">
            <div class="card__head"><h2>Evidence</h2></div>
            <pre class="evidence">${escapeHtml(
                JSON.stringify(finding.evidence || {}, null, 2)
            )}</pre>
        </section>
    `;

    if (canEdit) {
        wireWorkflow(finding);
    }
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

        render(payload.finding, Boolean(payload.can_edit));
    } catch (error) {
        view.innerHTML = `
            <div class="notice notice--error">
                ${escapeHtml(error.message || "Could not load the finding.")}
            </div>
        `;
    }
}


load();
