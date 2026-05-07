const express = require('express');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const { auth } = require('express-openid-connect');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
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

// Rate limiting limits how many requests an IP can make to stop flooding
// 30 requests per 15 minutes for general use
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: { error: 'Too many requests please try again later' }
});

//limit just for the login page to stop brute force flooding
//only 5 attempts per 15 minutes per IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts please wait and try again' }
});

// WAF middleware
// Checks each request for signs of attack tools or bots
const blockedUserAgents = ['masscan', 'nmap', 'sqlmap', 'nikto', 'dirbuster', 'gobuster', 'hydra'];

function wafMiddleware(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = (req.get('user-agent') || '').toLowerCase();

    //Block requests with no host header most real browsers always send this
    if (!req.get('host')) {
        console.warn('WAF missing host header from IP: ' + ip);
        return res.status(400).json({ error: 'Bad request' });
    }

    //Block known attack scanning tools by checking the user agent string
    for (let i = 0; i < blockedUserAgents.length; i++) {
        if (userAgent.includes(blockedUserAgents[i])) {
            console.warn('WAF blocked tool: ' + userAgent + ' from IP: ' + ip);
            return res.status(403).json({ error: 'Forbidden' });
        }
    }

    //Block requests with suspicious large headers
    const headerSize = JSON.stringify(req.headers).length;
    if (headerSize > 8000) {
        console.warn('WAF oversized headers from IP: ' + ip);
        return res.status(431).json({ error: 'Request header fields Too Large' });
    }

    next();
}

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

// Simple double submit check: token in the request must match token in the cookie.
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

//Apply WAF and rate limiter to all routes before anything else runs
app.use(wafMiddleware);
app.use(generalLimiter);

app.use(auth(authModule.createAuth0Config()));
app.use(createSecurityHeadersMiddleware());

//Limit body size to stop large payload attacks
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(setCsrfToken);
app.use(express.static(PATHS.publicDir));

//Apply stricter rate limit to login and signup before the routes are registered
app.post('/', loginLimiter);
app.post('/signup', loginLimiter);

authModule.registerRoutes(app, sessionTools, { validateCsrfToken });
registerPostRoutes(app, {
    pool,
    validateSession: sessionTools.validateSession,
    validateCsrfToken
});

app.use(handleUploadError);

pool.query('SELECT 1')
    .then(() => {
        const server = app.listen(PORT, () => {
            console.log(`My app listening on port ${PORT}!`);
        });

        // Set a timeout on connections helps against slowloris attacks where
        // attackers hold connections open without finishing their request
        server.setTimeout(10000);
    })
    .catch((error) => {
        console.error('Failed to connect to PostgreSQL:', error.message);
        process.exit(1);
    });
