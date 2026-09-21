/*
|--------------------------------------------------------------------------
| Application shell
|--------------------------------------------------------------------------
| Every page calls renderShell() with its scope and breadcrumbs; the rail,
| navigation drawer and top bar are produced here so navigation stays
| identical across the product and on every screen size.
*/

const PERIOD_KEY = "secguardPeriod";

const PERIODS = [
    { value: "3", label: "Last 3 months" },
    { value: "6", label: "Last 6 months" },
    { value: "12", label: "Last 12 months" },
];

const ICONS = {
    portfolio:
        '<path d="M3 3h7v7H3zM14 3h7v4h-7zM14 10h7v11h-7zM3 13h7v8H3z"/>',
    system:
        '<path d="M12 2 3 6.5v5c0 5 3.8 9.2 9 10.5 5.2-1.3 9-5.5 9-10.5v-5z"/>',
    overview:
        '<path d="M4 13h6V4H4zM14 20h6v-9h-6zM4 20h6v-5H4zM14 8h6V4h-6z"/>',
    security:
        '<path d="M12 2 4 5.5v6c0 4.6 3.4 8.4 8 9.5 4.6-1.1 8-4.9 8-9.5v-6z"/>',
    surface:
        '<path d="M12 2 2 8l10 6 10-6zM2 16l10 6 10-6-2.5-1.5L12 19 4.5 14.5z"/>',
    scan:
        '<path d="M11 3a8 8 0 1 0 4.9 14.3l4.4 4.4 1.4-1.4-4.4-4.4A8 8 0 0 0 11 3m0 2a6 6 0 1 1 0 12 6 6 0 0 1 0-12"/>',
    settings:
        '<path d="M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8m9 4-2-.6a7 7 0 0 0-.7-1.7l1-1.8-1.6-1.6-1.8 1a7 7 0 0 0-1.7-.7L13.6 3h-3.2L9.8 5a7 7 0 0 0-1.7.7l-1.8-1L4.7 6.3l1 1.8a7 7 0 0 0-.7 1.7L3 10.4v3.2l2 .6c.2.6.4 1.2.7 1.7l-1 1.8 1.6 1.6 1.8-1c.5.3 1.1.5 1.7.7l.6 2h3.2l.6-2c.6-.2 1.2-.4 1.7-.7l1.8 1 1.6-1.6-1-1.8c.3-.5.5-1.1.7-1.7l2-.6z"/>',
};


function icon(name) {
    return `
        <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
            ${ICONS[name] || ""}
        </svg>
    `;
}


function currentPeriod() {
    const stored = localStorage.getItem(PERIOD_KEY);

    return PERIODS.some(period => period.value === stored)
        ? stored
        : "12";
}


function periodMonths() {
    return Number(currentPeriod());
}


function periodLabel() {
    const months = periodMonths();

    const end = new Date();

    const start = new Date(
        end.getFullYear(),
        end.getMonth() - (months - 1),
        1
    );

    const format = date =>
        date.toLocaleDateString("en-US", {
            month: "short",
            year: "numeric",
        });

    return `${format(start)} - ${format(end)}`;
}


function navigationFor(scope, active, applicationId) {
    const suffix = applicationId
        ? `?application=${encodeURIComponent(applicationId)}`
        : "";

    if (scope === "system") {
        return {
            title: "System",
            groups: [
                {
                    label: "",
                    links: [
                        {
                            id: "overview",
                            icon: "overview",
                            text: "System Overview",
                            href: `/application.html${suffix}`,
                        },
                    ],
                },
                {
                    label: "Quality Aspects",
                    links: [
                        {
                            id: "security",
                            icon: "security",
                            text: "Security",
                            href: `/system-security.html${suffix}`,
                        },
                        {
                            id: "surface",
                            icon: "surface",
                            text: "Attack Surface",
                            href: `/attack-surface.html${suffix}`,
                        },
                    ],
                },
                {
                    label: "Findings",
                    links: [
                        {
                            id: "findings",
                            icon: "security",
                            text: "All Findings",
                            href: `/findings.html${suffix}`,
                        },
                    ],
                },
            ],
        };
    }

    return {
        title: "Portfolio",
        groups: [
            {
                label: "",
                links: [
                    {
                        id: "overview",
                        icon: "overview",
                        text: "Portfolio Overview",
                        href: "/dashboard.html",
                    },
                ],
            },
            {
                label: "Quality Aspects",
                links: [
                    {
                        id: "security",
                        icon: "security",
                        text: "Security",
                        href: "/portfolio-security.html",
                    },
                ],
            },
            {
                label: "Analysis",
                links: [
                    {
                        id: "scan",
                        icon: "scan",
                        text: "New Scan",
                        href: "/index.html",
                    },
                    {
                        id: "settings",
                        icon: "settings",
                        text: "Settings",
                        href: "/settings.html",
                    },
                ],
            },
        ],
    };
}


function breadcrumbMarkup(trail) {
    return trail
        .map((crumb, position) => {
            const last = position === trail.length - 1;

            const label = escapeHtml(crumb.text);

            const node = crumb.href && !last
                ? `<a href="${escapeHtml(crumb.href)}">${label}</a>`
                : `<span${last ? ' aria-current="page"' : ""}>${label}</span>`;

            return position === 0
                ? node
                : `<span class="sep">&rsaquo;</span>${node}`;
        })
        .join("");
}


/**
 * Render the shell and return the element pages should fill.
 *
 * options: { scope, active, applicationId, breadcrumbs, period, tools }
 */
function renderShell(options) {
    const settings = options || {};

    const scope = settings.scope || "portfolio";

    const applicationId =
        settings.applicationId || currentApplicationId();

    const navigation = navigationFor(
        scope,
        settings.active,
        applicationId
    );

    const railItems = [
        {
            id: "portfolio",
            text: "Portfolio",
            href: "/dashboard.html",
            scope: "portfolio",
        },
        {
            id: "system",
            text: "System",
            href: applicationId
                ? `/system-security.html?application=${encodeURIComponent(
                    applicationId
                )}`
                : "/dashboard.html",
            scope: "system",
        },
    ];

    const groups = navigation.groups
        .map(group => `
            ${group.label
                ? `<div class="nav__group">${escapeHtml(group.label)}</div>`
                : ""}

            ${group.links
                .map(link => `
                    <a
                        class="nav__link ${
                            link.id === settings.active ? "is-active" : ""
                        }"
                        href="${escapeHtml(link.href)}"
                    >
                        ${icon(link.icon)}
                        <span>${escapeHtml(link.text)}</span>
                    </a>
                `)
                .join("")}
        `)
        .join("");

    const periodChip = settings.period === false
        ? ""
        : `
            <label class="chip" for="periodSelect">
                <span id="periodLabel">${escapeHtml(periodLabel())}</span>
                <select
                    id="periodSelect"
                    aria-label="Reporting period"
                    style="border:0;background:none;padding:0;width:auto"
                >
                    ${PERIODS.map(period => `
                        <option
                            value="${period.value}"
                            ${period.value === currentPeriod()
                                ? "selected"
                                : ""}
                        >
                            ${period.label}
                        </option>
                    `).join("")}
                </select>
            </label>
        `;

    document.body.innerHTML = `
        <div class="app">

            <nav class="rail" aria-label="Sections">

                <a class="rail__brand" href="/dashboard.html" title="SecGuard">
                    S
                </a>

                ${railItems
                    .map(item => `
                        <a
                            class="rail__item ${
                                item.scope === scope ? "is-active" : ""
                            }"
                            href="${escapeHtml(item.href)}"
                        >
                            ${icon(item.id)}
                            <span>${escapeHtml(item.text)}</span>
                        </a>
                    `)
                    .join("")}

                <div class="rail__spacer"></div>

            </nav>

            <aside class="nav" id="navDrawer" aria-label="Navigation">

                <div class="nav__head">

                    <div class="nav__title">
                        ${escapeHtml(navigation.title)}
                    </div>

                    <button
                        class="nav__close"
                        id="navClose"
                        type="button"
                        aria-label="Close navigation"
                    >
                        &times;
                    </button>

                </div>

                ${groups}

            </aside>

            <div class="scrim" id="navScrim"></div>

            <div class="main">

                <header class="topbar">

                    <button
                        class="topbar__menu"
                        id="navToggle"
                        type="button"
                        aria-label="Open navigation"
                        aria-expanded="false"
                    >
                        &#9776;
                    </button>

                    <div class="breadcrumbs">
                        ${breadcrumbMarkup(settings.breadcrumbs || [])}
                    </div>

                    <div class="topbar__tools">
                        ${periodChip}
                        ${settings.tools || ""}
                    </div>

                </header>

                <main class="content" id="view"></main>

            </div>

        </div>
    `;

    const toggle = document.getElementById("navToggle");
    const close = document.getElementById("navClose");
    const scrim = document.getElementById("navScrim");

    const setOpen = open => {
        document.body.classList.toggle("nav-open", open);
        toggle.setAttribute("aria-expanded", String(open));
    };

    toggle.addEventListener("click", () =>
        setOpen(!document.body.classList.contains("nav-open"))
    );

    close.addEventListener("click", () => setOpen(false));
    scrim.addEventListener("click", () => setOpen(false));

    document.addEventListener("keydown", event => {
        if (event.key === "Escape") {
            setOpen(false);
        }
    });

    const period = document.getElementById("periodSelect");

    if (period) {
        period.addEventListener("change", () => {
            localStorage.setItem(PERIOD_KEY, period.value);

            document.getElementById("periodLabel").textContent =
                periodLabel();

            window.dispatchEvent(new CustomEvent("periodchange"));
        });
    }

    return document.getElementById("view");
}
