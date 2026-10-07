/*
|--------------------------------------------------------------------------
| Sign-in page
|--------------------------------------------------------------------------
| Shown before any other page when GitHub sign-in is configured. The
| server also renders it, with an error status, when GitHub sends the
| browser back without a usable sign-in.
*/

const GITHUB_MARK = `
    <svg viewBox="0 0 16 16" width="20" height="20" aria-hidden="true" fill="currentColor">
        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
    </svg>
`;


function nextPage() {
    const value = new URLSearchParams(window.location.search).get("next") || "";

    // Only SecGuard's own pages; the server checks this again.
    return /^\/(?![/\\])/.test(value) ? value : "/applications.html";
}


function failureNotice() {
    if (!window.location.pathname.startsWith("/auth/github/")) {
        return "";
    }

    return `
        <div class="notice notice--error" role="alert">
            GitHub sign-in did not complete. Please try again.
        </div>
    `;
}


function signInMarkup(me) {
    if (!me.github_enabled) {
        return `
            <div class="notice">
                GitHub sign-in is not set up on this server. An administrator
                needs to set <code>SECGUARD_GITHUB_CLIENT_ID</code> and
                <code>SECGUARD_GITHUB_CLIENT_SECRET</code>.
            </div>
            <a class="button button--ghost login__action" href="/dashboard.html">
                Continue to SecGuard
            </a>
        `;
    }

    if (me.authenticated) {
        return `
            <p>Signed in as <strong>${escapeHtml(me.user.login)}</strong>.</p>
            <a class="button login__action" href="/applications.html">
                Go to My Applications
            </a>
        `;
    }

    const href = `/auth/github/login?next=${encodeURIComponent(nextPage())}`;

    return `
        ${failureNotice()}
        <a class="button login__action login__github" href="${escapeHtml(href)}">
            ${GITHUB_MARK}
            <span>Sign in with GitHub</span>
        </a>
        <p class="login__fine">
            You will be sent to GitHub to confirm it is you. If you are
            already signed in to GitHub and have approved SecGuard before,
            you come straight back.
        </p>
    `;
}


async function load() {
    const me = await currentUser();

    document.body.innerHTML = `
        <main class="login">
            <section class="login__card">
                <div class="login__brand">
                    <span class="login__logo" aria-hidden="true">S</span>
                    <span>SecGuard</span>
                </div>
                <h1>Sign in</h1>
                <p class="muted">
                    Use your GitHub account. You will see the applications
                    your GitHub account has access to.
                </p>
                ${signInMarkup(me)}
            </section>
        </main>
    `;
}


load();
