const crypto = require('crypto');
const { hashPassword, verifyPassword } = require('../security/passwordHashing');
const { normalizeEmail, validateSignupInput } = require('../security/signupValidation');
const {
    ENV,
    LIMITS,
    PATTERNS,
    PATHS,
    OAUTH_CONNECTIONS,
    SESSION_COOKIE_OPTIONS
} = require('./config');
const {
    getSafeString,
    isWithinMaxLength,
    getRequestIp,
    getUserAgent,
    sendPage
} = require('./utils');

function createAuthModule({ pool, loginState }) {
    function isOidcAuthenticated(req) {
        return Boolean(req.oidc && typeof req.oidc.isAuthenticated === 'function' && req.oidc.isAuthenticated());
    }

    function sendLoginPage(res) {
        return sendPage(res, PATHS.loginPage);
    }

    function sendIndexPage(res) {
        return sendPage(res, PATHS.indexPage);
    }

    function getOidcUsername(oidcUser) {
        if (!oidcUser) {
            return '';
        }

        return getSafeString(oidcUser.email) ||
            getSafeString(oidcUser.preferred_username) ||
            getSafeString(oidcUser.nickname) ||
            getSafeString(oidcUser.name) ||
            getSafeString(oidcUser.sub);
    }

    async function getDisplayNameForUser(username) {
        if (!username) {
            return '';
        }

        try {
            const result = await pool.query(
                'SELECT display_name FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1',
                [username]
            );
            return getSafeString(result.rows[0]?.display_name);
        } catch (error) {
            console.error('Failed to fetch display name:', error.message);
            return '';
        }
    }

    function sanitizeDisplayName(value) {
        const safe = getSafeString(value)
            .trim()
            .replace(/[^A-Za-z0-9_]/g, '_')
            .replace(/^_+|_+$/g, '');

        if (safe.length < 3) {
            return '';
        }

        return safe.slice(0, 20);
    }

    function deriveDisplayNameFromOidc(oidcUser) {
        if (!oidcUser) {
            return `user_${crypto.randomBytes(3).toString('hex')}`.slice(0, 20);
        }

        const candidates = [
            sanitizeDisplayName(oidcUser.name),
            sanitizeDisplayName(oidcUser.preferred_username),
            sanitizeDisplayName(oidcUser.nickname),
            sanitizeDisplayName(oidcUser.email),
            sanitizeDisplayName(oidcUser.sub)
        ];

        for (const candidate of candidates) {
            if (PATTERNS.displayName.test(candidate)) {
                return candidate;
            }
        }

        return `user_${crypto.randomBytes(3).toString('hex')}`.slice(0, 20);
    }

    async function makeUniqueDisplayName(baseName, excludedUsername = '') {
        const excludedUsernameLower = getSafeString(excludedUsername).toLowerCase();
        let candidate = baseName.slice(0, 20);
        let suffix = 2;

        while (true) {
            const result = await pool.query(
                'SELECT username FROM users WHERE LOWER(display_name) = LOWER($1) LIMIT 1',
                [candidate]
            );

            const matchedUsername = getSafeString(result.rows[0]?.username).toLowerCase();
            if (result.rowCount === 0 || matchedUsername === excludedUsernameLower) {
                return candidate;
            }

            const suffixText = `_${suffix}`;
            candidate = `${baseName.slice(0, 20 - suffixText.length)}${suffixText}`;
            suffix += 1;
        }
    }

    async function ensureOauthUser(oidcUser) {
        const username = getOidcUsername(oidcUser);

        if (!username) {
            return;
        }

        const baseDisplayName = deriveDisplayNameFromOidc(oidcUser);
        const existingUserResult = await pool.query(
            'SELECT display_name FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1',
            [username]
        );

        if (existingUserResult.rowCount > 0) {
            const currentDisplayName = getSafeString(existingUserResult.rows[0].display_name);

            if (currentDisplayName === '' || currentDisplayName.toLowerCase() === username.toLowerCase()) {
                const displayName = await makeUniqueDisplayName(baseDisplayName, username);
                await pool.query(
                    'UPDATE users SET display_name = $1 WHERE LOWER(username) = LOWER($2)',
                    [displayName, username]
                );
            }

            return;
        }

        const displayName = await makeUniqueDisplayName(baseDisplayName, username);
        const randomPassword = crypto.randomBytes(32).toString('hex');
        const passwordHash = await hashPassword(randomPassword);

        await pool.query(
            'INSERT INTO users (username, display_name, password) VALUES ($1, $2, $3)',
            [username, displayName, passwordHash]
        );
    }

    async function verifyRecaptchaToken(token, remoteIp) {
        try {
            const body = new URLSearchParams();
            body.append('secret', ENV.recaptchaSecretKey);
            body.append('response', token);

            if (remoteIp) {
                body.append('remoteip', remoteIp);
            }

            const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body
            });

            if (!response.ok) {
                return false;
            }

            const verificationResult = await response.json();
            return verificationResult.success === true;
        } catch (error) {
            console.error('reCAPTCHA verification failed:', error.message);
            return false;
        }
    }

    function failLogin(status, res) {
        loginState.clearCurrentUser();
        loginState.setLoginStatus(status);
        return sendLoginPage(res);
    }

    async function clearExistingSessions(username) {
        try {
            await pool.query(
                'UPDATE sessions SET is_active = false WHERE username = $1',
                [username]
            );
        } catch (error) {
            console.error('Failed to cleanup old sessions:', error.message);
        }
    }

    async function handleLocalLogin(req, res) {
        const usernameInput = getSafeString(req.body.username_input).trim();
        const username = usernameInput.includes('@') ? normalizeEmail(usernameInput) : usernameInput;
        const password = getSafeString(req.body.password_input);

        if (username === '' || password === '') {
            return failLogin('empty', res);
        }

        if (
            !isWithinMaxLength(username, LIMITS.maxEmailLength) ||
            !isWithinMaxLength(password, LIMITS.maxPasswordLength)
        ) {
            return failLogin('invalid', res);
        }

        const recaptchaToken = getSafeString(req.body['g-recaptcha-response']);
        if (recaptchaToken === '') {
            return failLogin('captcha_required', res);
        }

        if (!isWithinMaxLength(recaptchaToken, LIMITS.maxRecaptchaTokenLength)) {
            return failLogin('captcha_failed', res);
        }

        const recaptchaVerified = await verifyRecaptchaToken(recaptchaToken, getRequestIp(req));
        if (!recaptchaVerified) {
            return failLogin('captcha_failed', res);
        }

        try {
            const userResult = await pool.query(
                'SELECT username, password FROM users WHERE username = $1 LIMIT 1',
                [username]
            );

            if (userResult.rows.length === 0) {
                return failLogin('invalid', res);
            }

            const passwordMatches = await verifyPassword(password, userResult.rows[0].password);
            if (!passwordMatches) {
                return failLogin('invalid', res);
            }

            await clearExistingSessions(username);

            const sessionId = crypto.randomBytes(32).toString('hex');

            try {
                await pool.query(
                    `INSERT INTO sessions (session_id, username, ip_address, user_agent, is_active)
                     VALUES ($1, $2, $3, $4, true)`,
                    [sessionId, username, getRequestIp(req), getUserAgent(req)]
                );
            } catch (error) {
                console.error('Failed to create session:', error.message);
                return failLogin('server_error', res);
            }

            res.cookie('session_id', sessionId, SESSION_COOKIE_OPTIONS);
            loginState.setCurrentUser(username);
            loginState.setLoginStatus('success');
            return sendIndexPage(res);
        } catch (error) {
            console.error('Login query failed:', error.message);
            return failLogin('server_error', res);
        }
    }

    async function handleSignup(req, res) {
        const validation = validateSignupInput(
            getSafeString(req.body.signup_username_input),
            getSafeString(req.body.signup_email_input),
            getSafeString(req.body.signup_password_input),
            getSafeString(req.body.signup_password_confirm_input)
        );

        if (!validation.ok || !isWithinMaxLength(validation.email, LIMITS.maxEmailLength)) {
            return res.redirect('/?mode=signup&signup=' + encodeURIComponent(validation.code || 'invalid'));
        }

        try {
            const duplicateUserResult = await pool.query(
                'SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1',
                [validation.email]
            );

            if (duplicateUserResult.rows.length > 0) {
                return res.redirect('/?mode=signup&signup=duplicate');
            }

            const duplicateDisplayNameResult = await pool.query(
                'SELECT 1 FROM users WHERE LOWER(display_name) = LOWER($1) LIMIT 1',
                [validation.displayName]
            );

            if (duplicateDisplayNameResult.rows.length > 0) {
                return res.redirect('/?mode=signup&signup=duplicate_username');
            }

            const passwordHash = await hashPassword(getSafeString(req.body.signup_password_input));
            await pool.query(
                'INSERT INTO users (username, display_name, password) VALUES ($1, $2, $3)',
                [validation.email, validation.displayName, passwordHash]
            );

            return res.redirect('/?mode=login&signup=created');
        } catch (error) {
            if (error && error.code === '23505') {
                return res.redirect('/?mode=signup&signup=duplicate');
            }

            console.error('Sign-up failed:', error.message);
            return res.redirect('/?mode=signup&signup=server_error');
        }
    }

    function createOauthLoginHandler(connection) {
        return (req, res) => {
            if (isOidcAuthenticated(req)) {
                return res.redirect('/');
            }

            return res.oidc.login({
                returnTo: '/',
                authorizationParams: { connection }
            });
        };
    }

    async function buildCurrentUserResponse(req) {
        const oidcUser = isOidcAuthenticated(req) ? req.oidc.user : null;
        const username = oidcUser ? getOidcUsername(oidcUser) : (loginState.getCurrentUser() || '');

        if (!username) {
            return { username: null, displayName: null, isAuthenticated: false };
        }

        if (oidcUser) {
            await ensureOauthUser(oidcUser);
        }

        const displayName = await getDisplayNameForUser(username);
        return {
            username,
            displayName: displayName || (oidcUser ? deriveDisplayNameFromOidc(oidcUser) : username),
            isAuthenticated: true
        };
    }

    function createAuth0Config() {
        return {
            authRequired: false,
            auth0Logout: true,
            secret: ENV.auth0Secret,
            baseURL: ENV.auth0BaseURL,
            clientID: ENV.auth0ClientID,
            issuerBaseURL: ENV.auth0IssuerBaseURL,
            afterCallback: async (req, res, session) => {
                await ensureOauthUser(session.user);
                return session;
            }
        };
    }

    function registerRoutes(app, { isValidSessionId, deactivateSessionById }) {
        app.get('/auth/status', (req, res) => {
            res.json({
                isLoggedIn: isOidcAuthenticated(req),
                user: req.oidc?.user ?? null
            });
        });

        app.get('/login/google', createOauthLoginHandler(OAUTH_CONNECTIONS.google));
        app.get('/login/github', createOauthLoginHandler(OAUTH_CONNECTIONS.github));

        app.get('/', (req, res) => {
            return isOidcAuthenticated(req) ? sendIndexPage(res) : sendLoginPage(res);
        });

        app.get('/login-status', (req, res) => {
            res.json({ status: loginState.getLoginStatus() });
        });

        app.get('/current-user', async (req, res) => {
            try {
                return res.json(await buildCurrentUserResponse(req));
            } catch (error) {
                console.error('Failed to resolve current user:', error.message);
                return res.json({ username: null, displayName: null, isAuthenticated: false });
            }
        });

        app.get('/app-logout', async (req, res) => {
            const sessionId = req.cookies.session_id;

            if (sessionId && isValidSessionId(sessionId)) {
                try {
                    await deactivateSessionById(sessionId);
                } catch (error) {
                    console.error('Failed to log out session:', error.message);
                }
            }

            res.clearCookie('session_id');
            loginState.reset();

            if (isOidcAuthenticated(req)) {
                return res.oidc.logout({ returnTo: ENV.auth0BaseURL || '/' });
            }

            return res.redirect('/');
        });

        app.get('/captcha-config', (req, res) => {
            res.json({ siteKey: ENV.recaptchaSiteKey });
        });

        app.post('/', handleLocalLogin);
        app.post('/signup', handleSignup);
    }

    return {
        createAuth0Config,
        registerRoutes,
        getOidcUsername
    };
}

module.exports = {
    createAuthModule
};
