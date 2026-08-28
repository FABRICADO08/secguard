/*
|--------------------------------------------------------------------------
| Shared helpers
|--------------------------------------------------------------------------
*/

const SEVERITY_ORDER = [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
];


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


function severityBadge(
    severity
) {

    const value =
        String(severity || "informational")
            .toLowerCase();

    return `
        <span class="severity ${escapeHtml(value)}">
            ${escapeHtml(value)}
        </span>
    `;
}


function severityCounts(
    counts
) {

    return SEVERITY_ORDER
        .map(
            severity => `
                <div class="severity-count ${severity}">

                    <strong>
                        ${escapeHtml(
                            (counts || {})[severity] ?? 0
                        )}
                    </strong>

                    <span>
                        ${severity}
                    </span>

                </div>
            `
        )
        .join("");
}


function queryParameter(
    name
) {

    return new URLSearchParams(
        window.location.search
    ).get(name);
}


function currentApplicationId() {

    return (
        queryParameter("application") ||
        localStorage.getItem(
            "currentApplicationId"
        ) ||
        ""
    );
}


async function getJson(
    url
) {

    const response =
        await fetch(url);

    const data =
        await response.json();

    if (!response.ok) {

        throw new Error(
            data.error ||
            "Request failed."
        );

    }

    return data;
}
