const express = require('express');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const { auth } = require('express-openid-connect');
const crypto = require('crypto');
const {
    PORT,
    ENV,
    PATHS,
    assertRequiredConfig
} = require('./server/config');
const { createLoginState } = require('./server/loginState');
const { createSecurityHeadersMiddleware } = require('./server/middleware');
const { createAuthModule } = require('./server/auth');
const { createSessionTools } = require('./server/session');
const { registerPostRoutes, handleUploadError } = require('./server/posts');

assertRequiredConfig();

const app = express();
const pool = new Pool({
    connectionString: ENV.dbConnectionString,
    ssl: {
        rejectUnauthorized: false
    }
});

const loginState = createLoginState();
const authModule = createAuthModule({ pool, loginState });
const sessionTools = createSessionTools({
    pool,
    getOidcUsername: authModule.getOidcUsername
});

const CSRF_COOKIE_NAME = 'csrf_token';

// Create a random token that the browser must send back with POST requests.
function createCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Give each browser a CSRF token cookie if it does not already have one.
function setCsrfToken(req, res, next) {
    if (!req.cookies[CSRF_COOKIE_NAME]) {
        res.cookie(CSRF_COOKIE_NAME, createCsrfToken(), {
            httpOnly: false,
            secure: false,
            sameSite: 'strict'
        });
    }

    next();
}

// Simple double-submit check: token in the request must match token in the cookie.
function validateCsrfToken(req, res, next) {
    const cookieToken = req.cookies[CSRF_COOKIE_NAME];
    const bodyToken = typeof req.body?.csrf_token === 'string' ? req.body.csrf_token : '';
    const headerToken = req.get('x-csrf-token') || '';
    const submittedToken = bodyToken || headerToken;

    if (!cookieToken || !submittedToken || cookieToken !== submittedToken) {
        if (req.path === '/') {
            loginState.setLoginStatus('csrf_invalid');
            return res.redirect('/');
        }

        if (req.path === '/signup') {
            return res.redirect('/?mode=signup');
        }

        return res.status(403).send('Invalid CSRF token.');
    }

    next();
}

app.disable('x-powered-by');
app.use(auth(authModule.createAuth0Config()));
app.use(createSecurityHeadersMiddleware());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(setCsrfToken);
app.use(express.static(PATHS.publicDir));

authModule.registerRoutes(app, sessionTools, { validateCsrfToken });
registerPostRoutes(app, {
    pool,
    validateSession: sessionTools.validateSession,
    validateCsrfToken
});

app.use(handleUploadError);

pool.query('SELECT 1')
    .then(() => {
        app.listen(PORT, () => {
            console.log(`My app listening on port ${PORT}!`);
        });
    })
    .catch((error) => {
        console.error('Failed to connect to PostgreSQL:', error.message);
        process.exit(1);
    });
