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

const SEVERITY_INITIAL = {
    critical: "C",
    high: "H",
    medium: "M",
    low: "L",
    informational: "I",
};

/*
 * The generic and platform rule catalogues tag findings with the 2021
 * OWASP Top 10, so the whole list is shown and categories without a
 * finding are reported as clean rather than omitted.
 */
const OWASP_TOP_TEN = [
    "A01:2021 Broken Access Control",
    "A02:2021 Cryptographic Failures",
    "A03:2021 Injection",
    "A04:2021 Insecure Design",
    "A05:2021 Security Misconfiguration",
    "A06:2021 Vulnerable and Outdated Components",
    "A07:2021 Identification and Authentication Failures",
    "A08:2021 Software and Data Integrity Failures",
    "A09:2021 Security Logging and Monitoring Failures",
    "A10:2021 Server-Side Request Forgery",
];

const UNCLASSIFIED = "Unclassified";


function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function titleCase(value) {
    const text = String(value || "");

    return text.charAt(0).toUpperCase() + text.slice(1);
}


function queryParameter(name) {
    return new URLSearchParams(window.location.search).get(name);
}


function currentApplicationId() {
    return (
        queryParameter("application") ||
        localStorage.getItem("currentApplicationId") ||
        ""
    );
}


function rememberApplication(applicationId) {
    if (applicationId) {
        localStorage.setItem("currentApplicationId", applicationId);
    }
}


const API_TOKEN_KEY = "secguardApiToken";


function apiToken() {
    return localStorage.getItem(API_TOKEN_KEY) || "";
}


/*
 * The scanning and delete endpoints require the token configured with
 * SECGUARD_API_TOKEN whenever the server was started with one.
 */
async function apiFetch(url, options) {
    const settings = { ...(options || {}) };

    const token = apiToken();

    if (token) {
        settings.headers = {
            ...(settings.headers || {}),
            "X-API-Key": token,
        };
    }

    return fetch(url, settings);
}


async function getJson(url) {
    const response = await apiFetch(url);

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "Request failed.");
    }

    return data;
}


/* ----------------------------------------------------------- formatting */

function formatDate(value) {
    if (!value) {
        return "-";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
    });
}


function formatDateTime(value) {
    if (!value) {
        return "-";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return `${formatDate(value)}, ${date.toLocaleTimeString("en-US", {
        hour: "numeric",
        minute: "2-digit",
    })}`;
}


function findingAge(value) {
    if (!value) {
        return "-";
    }

    const detected = new Date(value);

    if (Number.isNaN(detected.getTime())) {
        return "-";
    }

    const days = Math.max(
        0,
        Math.floor((Date.now() - detected.getTime()) / 86400000)
    );

    if (days < 31) {
        return `${days} D`;
    }

    if (days < 365) {
        return `${Math.floor(days / 30)} M`;
    }

    return `${Math.floor(days / 365)} Y`;
}


function monthLabel(month) {
    const [year, index] = String(month).split("-");

    const date = new Date(Number(year), Number(index) - 1, 1);

    return date.toLocaleDateString("en-US", { month: "short" });
}


/* ----------------------------------------------------------- components */

function ratingMarkup(rating) {
    const value = Number(rating || 0);

    const width = Math.max(0, Math.min(100, (value / 5) * 100));

    return `
        <span class="rating">
            <span
                class="rating__stars"
                role="img"
                aria-label="${value.toFixed(1)} out of 5 stars"
            >
                ★★★★★
                <span style="width:${width}%">★★★★★</span>
            </span>
            <span class="rating__value">(${value.toFixed(1)})</span>
        </span>
    `;
}


/* Mirrors backend/portfolio/summary.py so a rating never disagrees. */
function ratingFromScore(score) {
    const value = Math.min(Math.max(Number(score) || 0, 0), 100);

    return Math.round((5 - (value / 100) * 4.5) * 10) / 10;
}


function severityBar(counts) {
    const values = SEVERITY_ORDER.map(severity => ({
        severity,
        count: Number((counts || {})[severity] || 0),
    }));

    const total = values.reduce((sum, item) => sum + item.count, 0);

    if (!total) {
        return '<div class="severity-bar"></div>';
    }

    return `
        <div class="severity-bar">
            ${values
                .filter(item => item.count)
                .map(
                    item => `
                        <i
                            class="sev-${item.severity}"
                            style="width:${(item.count / total) * 100}%"
                            title="${item.count} ${item.severity}"
                        ></i>
                    `
                )
                .join("")}
        </div>
    `;
}


function deltaMarkup(value) {
    const delta = Number(value || 0);

    if (!delta) {
        return '<span class="kpi__delta delta-flat">= 0</span>';
    }

    const direction = delta > 0 ? "delta-up" : "delta-down";

    return `
        <span class="kpi__delta ${direction}">
            ${delta > 0 ? "+" : ""}${delta}
        </span>
    `;
}


function severityLegend(counts, deltas) {
    return `
        <div class="severity-legend">
            ${["critical", "high", "medium", "low"]
                .map(
                    severity => `
                        <div class="border-${severity}">
                            <div class="count">
                                ${Number((counts || {})[severity] || 0)}
                            </div>
                            ${deltas
                                ? deltaMarkup((deltas || {})[severity])
                                : ""}
                            <div class="name">${titleCase(severity)}</div>
                        </div>
                    `
                )
                .join("")}
        </div>
    `;
}


function severityChips(counts) {
    const chips = SEVERITY_ORDER.filter(
        severity => Number((counts || {})[severity] || 0) > 0
    ).map(
        severity => `
            <span class="chip-count ${severity}" title="${severity}">
                ${SEVERITY_INITIAL[severity]}
                ${Number(counts[severity])}
            </span>
        `
    );

    return chips.length
        ? chips.join(" ")
        : '<span class="muted">No findings</span>';
}


/*
 * Findings carry a 0-100 risk score; the tables show it on the familiar
 * 0-10 scale next to the severity initial.
 */
function riskChip(finding) {
    const severity = String(finding.severity || "informational");

    const score = Number((finding.risk || {}).score || 0) / 10;

    return `
        <span class="cvss sev-${severity}">
            ${score.toFixed(1)}
            ${SEVERITY_INITIAL[severity] || "I"}
        </span>
    `;
}


function severityRank(severity) {
    const index = SEVERITY_ORDER.indexOf(
        String(severity || "informational").toLowerCase()
    );

    return index === -1 ? SEVERITY_ORDER.length : index;
}


function sortFindings(findings) {
    return [...findings].sort(
        (left, right) =>
            severityRank(left.severity) - severityRank(right.severity) ||
            String(left.title || "").localeCompare(String(right.title || ""))
    );
}


function countBySeverity(findings) {
    const counts = {};

    SEVERITY_ORDER.forEach(severity => {
        counts[severity] = 0;
    });

    findings.forEach(finding => {
        const severity = String(
            finding.severity || "informational"
        ).toLowerCase();

        counts[severity] = (counts[severity] || 0) + 1;
    });

    return counts;
}


/* ------------------------------------------------------------- grouping */

const GROUPINGS = {
    owasp: {
        label: "OWASP Top 10 (2021)",
        of: finding => String(finding.owasp || "").trim() || UNCLASSIFIED,
        all: () => [...OWASP_TOP_TEN, UNCLASSIFIED],
    },
    category: {
        label: "Category",
        of: finding => titleCase(finding.category || UNCLASSIFIED),
        all: () => [],
    },
    severity: {
        label: "Severity",
        of: finding => titleCase(finding.severity || "informational"),
        all: () => SEVERITY_ORDER.map(titleCase),
    },
    platform: {
        label: "Platform",
        of: finding => String(finding.platform || "Generic"),
        all: () => [],
    },
};


function groupFindings(findings, grouping) {
    const definition = GROUPINGS[grouping] || GROUPINGS.owasp;

    const groups = new Map();

    definition.all().forEach(name => groups.set(name, []));

    findings.forEach(finding => {
        const name = definition.of(finding);

        if (!groups.has(name)) {
            groups.set(name, []);
        }

        groups.get(name).push(finding);
    });

    return [...groups.entries()].map(([name, items]) => ({
        name,
        findings: sortFindings(items),
        counts: countBySeverity(items),
    }));
}


/* ------------------------------------------------------------ CSV export */

function toCsv(rows) {
    return rows
        .map(row =>
            row
                .map(cell => `"${String(cell ?? "").replaceAll('"', '""')}"`)
                .join(",")
        )
        .join("\r\n");
}


function downloadCsv(filename, rows) {
    const blob = new Blob([toCsv(rows)], {
        type: "text/csv;charset=utf-8",
    });

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;
    link.download = filename;

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}


/* ---------------------------------------------------------------- charts */

/**
 * Grouped bar chart drawn as inline SVG so the product needs no
 * charting dependency and still scales with its container.
 */
function barChart(series, categories, options) {
    const settings = options || {};

    const width = 640;
    const height = 220;
    const padding = { top: 16, right: 8, bottom: 34, left: 30 };

    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;

    const maximum = Math.max(
        1,
        ...series.flatMap(entry => entry.values)
    );

    const slot = plotWidth / Math.max(1, categories.length);
    const barWidth = Math.max(
        2,
        (slot * 0.7) / Math.max(1, series.length)
    );

    const ticks = [0, 0.25, 0.5, 0.75, 1].map(fraction =>
        Math.round(maximum * fraction)
    );

    const gridlines = ticks
        .map(tick => {
            const y =
                padding.top + plotHeight - (tick / maximum) * plotHeight;

            return `
                <line
                    x1="${padding.left}" y1="${y}"
                    x2="${width - padding.right}" y2="${y}"
                    stroke="#e3e8ef"
                />
                <text x="${padding.left - 6}" y="${y + 3}" text-anchor="end">
                    ${tick}
                </text>
            `;
        })
        .join("");

    const bars = categories
        .map((category, index) => {
            const base = padding.left + slot * index + slot * 0.15;

            return series
                .map((entry, position) => {
                    const value = Number(entry.values[index] || 0);

                    const barHeight = (value / maximum) * plotHeight;

                    const x = base + position * barWidth;
                    const y = padding.top + plotHeight - barHeight;

                    return `
                        <rect
                            x="${x}" y="${y}"
                            width="${barWidth - 1}"
                            height="${Math.max(0, barHeight)}"
                            fill="${entry.color}"
                        >
                            <title>${escapeHtml(category)} –
                                ${escapeHtml(entry.name)}: ${value}</title>
                        </rect>
                        ${value
                            ? `<text
                                    x="${x + barWidth / 2}"
                                    y="${y - 4}"
                                    text-anchor="middle"
                                >${value}</text>`
                            : ""}
                    `;
                })
                .join("");
        })
        .join("");

    const labels = categories
        .map((category, index) => {
            const x = padding.left + slot * index + slot / 2;

            return `
                <text
                    x="${x}"
                    y="${height - 12}"
                    text-anchor="middle"
                >${escapeHtml(category)}</text>
            `;
        })
        .join("");

    return `
        <svg
            class="chart"
            viewBox="0 0 ${width} ${height}"
            preserveAspectRatio="xMidYMid meet"
            role="img"
            aria-label="${escapeHtml(settings.title || "Chart")}"
        >
            ${gridlines}
            ${bars}
            ${labels}
        </svg>

        <div class="chart-legend">
            ${series
                .map(
                    entry => `
                        <span>
                            <i style="background:${entry.color}"></i>
                            ${escapeHtml(entry.name)}
                        </span>
                    `
                )
                .join("")}
        </div>
    `;
}
