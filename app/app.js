const express = require('express')
const app = express();
const port = 3000;

var bodyParser = require('body-parser');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { verifyPassword } = require('./security/passwordHashing');
const {
    encryptForDatabase,
    decryptFromDatabase
} = require('./security/databaseEncryption');

dotenv.config({ path: path.join(__dirname, '.env') });

app.use(express.static(__dirname + '/public'));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

const dbConnectionString = process.env.DATABASE_URL;
const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY;
const recaptchaSecretKey = process.env.RECAPTCHA_SECRET_KEY;
const sessionTimeoutMinutes = 4;
const MAX_USERNAME_LENGTH = 64;
const MAX_PASSWORD_LENGTH = 256;
const MAX_RECAPTCHA_TOKEN_LENGTH = 4096;
const MAX_POST_ID_LENGTH = 32;
const MAX_POST_TITLE_LENGTH = 120;
const MAX_POST_CONTENT_LENGTH = 5000;
const SESSION_ID_PATTERN = /^[a-f0-9]{64}$/i;
const PLAIN_TEXT_ONLY_PATTERN = /[<>]/;

app.disable('x-powered-by');

app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        [
            "default-src 'self'",
            "script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/",
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
            "img-src 'self' data: https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/",
            "connect-src 'self' https://www.google.com/recaptcha/",
            "frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'"
        ].join('; ')
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    next();
});

if (!dbConnectionString) {
    console.error('Missing DATABASE_URL in app/.env.');
    process.exit(1);
}

if (!recaptchaSiteKey || !recaptchaSecretKey) {
    console.error('Missing RECAPTCHA_SITE_KEY or RECAPTCHA_SECRET_KEY in app/.env.');
    process.exit(1);
}

const pool = new Pool({
    connectionString: dbConnectionString,
    ssl: {
        rejectUnauthorized: false
    }
});

// Landing page
app.get('/', (req, res) => {
    /// send the static file
    res.sendFile(__dirname + '/public/html/login.html', (err) => {
        if (err){
            console.log(err);
        }
    })
});

// Store who is currently logged in
let currentUser = null;
let loginStatus = 'first_load';

function getSafeString(value) {
    return typeof value === 'string' ? value : '';
}

function isWithinMaxLength(value, maxLength) {
    return value.length <= maxLength;
}

function isValidSessionId(sessionId) {
    return typeof sessionId === 'string' && SESSION_ID_PATTERN.test(sessionId);
}

function isValidPostId(postId) {
    return postId === '' || (/^[0-9]+$/.test(postId) && isWithinMaxLength(postId, MAX_POST_ID_LENGTH));
}

function containsHtmlLikeInput(value) {
    return PLAIN_TEXT_ONLY_PATTERN.test(value);
}

function sendLoginPage(res) {
    res.sendFile(__dirname + '/public/html/login.html', (err) => {
        if (err){
            console.log(err);
        }
    });
}

function buildPostFromRow(row) {
    return {
        username: row.username,
        timestamp: row.created_at_display,
        postId: row.post_id,
        title: row.title,
        content: decryptFromDatabase(row.content)
    };
}

async function getNextPostId() {
    const postIdResult = await pool.query('SELECT post_id FROM posts');
    let maxId = 0;

    for (const row of postIdResult.rows) {
        const postId = Number.parseInt(row.post_id, 10);
        if (Number.isFinite(postId) && postId > maxId) {
            maxId = postId;
        }
    }

    return String(maxId + 1);
}

// Verify the token from the browser with Google's siteverify API
async function verifyRecaptchaToken(token, remoteIp) {
    try {
        const body = new URLSearchParams();
        body.append('secret', recaptchaSecretKey);
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

        // If Google did not respond successfully, treat it as verification failure
        if (!response.ok) {
            return false;
        }

        const verificationResult = await response.json();
        // Allow login only when Google marks the token as valid
        return verificationResult.success === true;
    } catch (error) {
        console.error('reCAPTCHA verification failed:', error.message);
        return false;
    }
}

app.get('/login-status', (req, res) => {
    res.json({ status: loginStatus });
});

app.get('/current-user', (req, res) => {
    res.json({ username: currentUser });
});

app.get('/posts-data', async (req, res) => {
    try {
        const postsResult = await pool.query(`
            SELECT post_id, username, created_at_display, title, content
            FROM posts
            ORDER BY
                CASE WHEN post_id ~ '^[0-9]+$' THEN post_id::integer ELSE 0 END,
                post_id
        `);

        res.json(postsResult.rows.map(buildPostFromRow));
    } catch (error) {
        console.error('Failed to load encrypted posts:', error.message);
        res.status(500).json([]);
    }
});

// Expose only the public site key to the browser. Secret key stays server-side
app.get('/captcha-config', (req, res) => {
    res.json({ siteKey: recaptchaSiteKey });
});

// Ping endpoint - updates last_activity to keep session alive on any user interaction
app.get('/ping', validateSession, (req, res) => {
    res.json({ status: 'ok', username: req.currentUser });
});

// Login POST request
app.post('/', async function(req, res){

    // Step 1: Extracts username and password from the form
    var username = getSafeString(req.body.username_input).trim();
    var password = getSafeString(req.body.password_input);

    // Step 2: Check for empty fields
    if (username === '' || password === '') {
        currentUser = null;
        loginStatus = 'empty';
        return sendLoginPage(res);
    }

    // Reject malformed or oversized input before it reaches the database layer
    if (
        !isWithinMaxLength(username, MAX_USERNAME_LENGTH) ||
        !isWithinMaxLength(password, MAX_PASSWORD_LENGTH)
    ) {
        currentUser = null;
        loginStatus = 'invalid';
        return sendLoginPage(res);
    }

    // Step 3: Validate reCAPTCHA token before checking credentials
    const recaptchaToken = getSafeString(req.body['g-recaptcha-response']);
    if (recaptchaToken === '') {
        currentUser = null;
        loginStatus = 'captcha_required';
        return sendLoginPage(res);
    }

    if (!isWithinMaxLength(recaptchaToken, MAX_RECAPTCHA_TOKEN_LENGTH)) {
        currentUser = null;
        loginStatus = 'captcha_failed';
        return sendLoginPage(res);
    }

    const recaptchaVerified = await verifyRecaptchaToken(
        recaptchaToken,
        req.ip || req.connection.remoteAddress
    );

    if (!recaptchaVerified) {
        currentUser = null;
        loginStatus = 'captcha_failed';
        return sendLoginPage(res);
    }

    // Step 4: Query the database for the user and validate credentials
    try {
        // Legacy column name: users.password now stores a bcrypt hash, not plaintext.
        const userResult = await pool.query(
            'SELECT username, password FROM users WHERE username = $1 LIMIT 1',
            [username]
        );

        // Step 5: Check if user exists and if password matches
        if (userResult.rows.length === 0) {
            currentUser = null;
            loginStatus = 'invalid';
            return sendLoginPage(res);
        }

        const passwordMatches = await verifyPassword(password, userResult.rows[0].password);

        if (!passwordMatches) {
            currentUser = null;
            loginStatus = 'invalid';
            return sendLoginPage(res);
        }

        // Step 6: Invalidate all old sessions for this user
        try {
            await pool.query(
                `UPDATE sessions SET is_active = false WHERE username = $1`,
                [username]
            );
        } catch (cleanupError) {
            console.error('Failed to cleanup old sessions:', cleanupError.message);
            // Continue anyway, don't block login
        }

        // Step 7: Generate a new session ID
        const sessionId = crypto.randomBytes(32).toString('hex');
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.get('user-agent') || '';

        // Step 8: Create session in database
        try {
            await pool.query(
                `INSERT INTO sessions (session_id, username, ip_address, user_agent, is_active)
                 VALUES ($1, $2, $3, $4, true)`,
                [sessionId, username, ipAddress, userAgent]
            );
        } catch (sessionError) {
            console.error('Failed to create session:', sessionError.message);
            loginStatus = 'server_error';
            return sendLoginPage(res);
        }

        // Step 9: Set session cookie
        res.cookie('session_id', sessionId, {
            httpOnly: true,
            secure: false, // Set to true in production with HTTPS
            sameSite: 'lax',
            maxAge: 30 * 60 * 1000 // 30 minutes
        });

        loginStatus = 'success';
        currentUser = username;

        return res.sendFile(__dirname + '/public/html/index.html', (err) => {
            if (err){
                console.log(err);
            }
        });
    } catch (error) {
        console.error('Login query failed:', error.message);
        currentUser = null;
        loginStatus = 'server_error';
        return sendLoginPage(res);
    }
});

// Session Validation Middleware - Prevents Session Hijacking
async function validateSession(req, res, next) {
    const handleSessionFailure = async () => {
        res.clearCookie('session_id');

        // /ping is called via fetch, so return JSON + 401 for reliable client-side handling
        if (req.path === '/ping') {
            return res.status(401).json({ status: 'session_invalid' });
        }

        return res.redirect('/');
    };

    const sessionId = req.cookies.session_id;
    const currentIp = req.ip || req.connection.remoteAddress;
    const currentUserAgent = req.get('user-agent') || '';

    // Step 1: Check if session cookie exists
    if (!sessionId) {
        console.warn('No session cookie found');
        return handleSessionFailure();
    }

    if (!isValidSessionId(sessionId)) {
        console.warn('Malformed session cookie received');
        return handleSessionFailure();
    }

    try {
        // Step 2: Query database for this session
        const sessionResult = await pool.query(
            `SELECT *, EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - last_activity)) / 60 AS minutes_elapsed
             FROM sessions
             WHERE session_id = $1 AND is_active = true`,
            [sessionId]
        );

        // Step 3: Check if session exists and is active
        if (sessionResult.rows.length === 0) {
            console.warn('Session not found or inactive:', sessionId);
            return handleSessionFailure();
        }

        const session = sessionResult.rows[0];

        // Step 4: Check if session has timed out using database time difference
        const minutesElapsed = Number(session.minutes_elapsed);

        if (!Number.isFinite(minutesElapsed) || minutesElapsed > sessionTimeoutMinutes) {
            console.warn('Session timeout for user:', session.username);
            await pool.query(
                `UPDATE sessions SET is_active = false WHERE session_id = $1`,
                [sessionId]
            );
            return handleSessionFailure();
        }

        // Step 5: Check if IP address matches (hijacking detection)
        if (session.ip_address !== currentIp) {
            console.warn('IP mismatch detected for session:', sessionId);
            console.warn('Original IP:', session.ip_address, 'Current IP:', currentIp);
           
            // Invalidate session due to suspicious activity
            await pool.query(
                `UPDATE sessions SET is_active = false WHERE session_id = $1`,
                [sessionId]
            );
            return handleSessionFailure();
        }

        // Step 6: Check if user-agent matches (device/browser change detection)
        if (session.user_agent !== currentUserAgent) {
            console.warn('User-agent mismatch detected for session:', sessionId);
            console.warn('Original user-agent:', session.user_agent);
            console.warn('Current user-agent:', currentUserAgent);
           
            // Invalidate session due to suspicious activity
            await pool.query(
                `UPDATE sessions SET is_active = false WHERE session_id = $1`,
                [sessionId]
            );
            return handleSessionFailure();
        }

        // Step 7: Update last_activity timestamp
        await pool.query(
            `UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = $1`,
            [sessionId]
        );

        // Step 8: Attach session info to request for use in route handlers
        req.session = session;
        req.currentUser = session.username;

        next();
    } catch (error) {
        console.error('Session validation error:', error.message);
        return handleSessionFailure();
    }
}

// Make a post POST request
app.post('/makepost', validateSession, async function(req, res) {
    try {
        let curDate = new Date();
        curDate = curDate.toLocaleString("en-GB");

        const submittedPostId = getSafeString(req.body.postId).trim();
        const title = getSafeString(req.body.title_field).trim();
        const content = getSafeString(req.body.content_field).trim();

        if (
            title === '' ||
            content === '' ||
            !isValidPostId(submittedPostId) ||
            !isWithinMaxLength(title, MAX_POST_TITLE_LENGTH) ||
            !isWithinMaxLength(content, MAX_POST_CONTENT_LENGTH)
        ) {
            return res.status(400).send('Invalid post data.');
        }

        // This blog treats post fields as plain text, so reject HTML-significant input.
        if (containsHtmlLikeInput(title) || containsHtmlLikeInput(content)) {
            return res.status(400).send('Posts must use plain text only.');
        }

        const postId = submittedPostId === '' ? await getNextPostId() : submittedPostId;
        const encryptedContent = encryptForDatabase(content);

        // posts.content is encrypted before storage; titles stay plaintext for listing/search.
        await pool.query(
            `INSERT INTO posts (post_id, username, created_at_display, title, content)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (post_id)
             DO UPDATE SET
                username = EXCLUDED.username,
                created_at_display = EXCLUDED.created_at_display,
                title = EXCLUDED.title,
                content = EXCLUDED.content`,
            [postId, req.currentUser, curDate, title, encryptedContent]
        );

        res.sendFile(__dirname + "/public/html/my_posts.html");
    } catch (error) {
        console.error('Failed to save encrypted post:', error.message);
        res.status(500).send('Unable to save post.');
    }
 });

 // Delete a post POST request
 app.post('/deletepost', validateSession, async (req, res) => {
    try {
        const postId = getSafeString(req.body.postId).trim();

        if (!/^[0-9]+$/.test(postId) || !isWithinMaxLength(postId, MAX_POST_ID_LENGTH)) {
            return res.status(400).send('Invalid post ID.');
        }

        await pool.query(
            'DELETE FROM posts WHERE post_id = $1',
            [postId]
        );

        res.sendFile(__dirname + "/public/html/my_posts.html");
    } catch (error) {
        console.error('Failed to delete post:', error.message);
        res.status(500).send('Unable to delete post.');
    }
 });

pool.query('SELECT 1')
    .then(() => {
        app.listen(port, () => {
            console.log(`My app listening on port ${port}!`)
        });
    })
    .catch((error) => {
        console.error('Failed to connect to PostgreSQL:', error.message);
        process.exit(1);
    });
