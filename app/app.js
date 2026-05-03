const express = require('express')
const app = express();
const port = 3000;

var bodyParser = require('body-parser');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const {
    hashPassword,
    verifyPassword
} = require('./security/passwordHashing');
const {
    normalizeEmail,
    validateSignupInput
} = require('./security/signupValidation');
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
const MAX_EMAIL_LENGTH = 254;
const MAX_RECAPTCHA_TOKEN_LENGTH = 4096;
const MAX_POST_ID_LENGTH = 32;
const MAX_POST_TITLE_LENGTH = 120;
const MAX_POST_CONTENT_LENGTH = 5000;
const MAX_IMAGES_PER_POST = 5;
const MAX_IMAGE_SIZE_BYTES = 2 * 1024 * 1024;
const ALLOWED_IMAGE_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const SESSION_ID_PATTERN = /^[a-f0-9]{64}$/i;
const PLAIN_TEXT_ONLY_PATTERN = /[<>]/;

// Multer handles in-memory image uploads for posts
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: MAX_IMAGE_SIZE_BYTES,
        files: MAX_IMAGES_PER_POST
    },
    fileFilter: (req, file, cb) => {
        if (ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype)) {
            return cb(null, true);
        }

        const error = new Error('Invalid image type.');
        error.code = 'INVALID_IMAGE_TYPE';
        return cb(error);
    }
});

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

function parsePostId(postId) {
    if (postId === '') {
        return null;
    }

    if (!/^[0-9]+$/.test(postId) || !isWithinMaxLength(postId, MAX_POST_ID_LENGTH)) {
        return null;
    }

    const parsed = Number.parseInt(postId, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return null;
    }

    return parsed;
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
        username: row.author_name || 'Unknown user',
        timestamp: row.created_at_display,
        postId: row.post_id,
        title: row.title,
        content: decryptFromDatabase(row.content)
    };
}

async function getNextPostId() {
    const postIdResult = await pool.query('SELECT COALESCE(MAX(post_id), 0) AS max_id FROM posts');
    const maxId = Number(postIdResult.rows[0]?.max_id) || 0;
    return maxId + 1;
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
            SELECT
                posts.post_id,
                COALESCE(
                    NULLIF(users.display_name, ''),
                    CASE
                        WHEN posts.username LIKE '%@%' THEN split_part(posts.username, '@', 1)
                        WHEN NULLIF(posts.username, '') IS NOT NULL THEN posts.username
                        ELSE 'Unknown user'
                    END
                ) AS author_name,
                posts.created_at_display,
                posts.title,
                posts.content
            FROM posts
            LEFT JOIN users ON LOWER(users.username) = LOWER(posts.username)
            ORDER BY posts.post_id
        `);

        res.json(postsResult.rows.map(buildPostFromRow));
    } catch (error) {
        console.error('Failed to load encrypted posts:', error.message);
        res.status(500).json([]);
    }
});

// Return image metadata for a post
app.get('/post-images-data', validateSession, async (req, res) => {
    try {
        const postId = parsePostId(getSafeString(req.query.postId || '').trim());

        if (postId === null) {
            return res.status(400).json([]);
        }

        const imagesResult = await pool.query(
            `SELECT image_id, mime_type, size_bytes
             FROM post_images
             WHERE post_id = $1
             ORDER BY sort_order, image_id`,
            [postId]
        );

        res.json(imagesResult.rows.map((row) => ({
            imageId: row.image_id,
            mimeType: row.mime_type,
            sizeBytes: row.size_bytes
        })));
    } catch (error) {
        console.error('Failed to load post images:', error.message);
        res.status(500).json([]);
    }
});

// Serve the image bytes for a single image
app.get('/post-images/:imageId', validateSession, async (req, res) => {
    try {
        const imageId = Number.parseInt(String(req.params.imageId || ''), 10);

        if (!Number.isFinite(imageId)) {
            return res.status(400).end();
        }

        const imageResult = await pool.query(
            'SELECT image_data, mime_type FROM post_images WHERE image_id = $1',
            [imageId]
        );

        if (imageResult.rows.length === 0) {
            return res.status(404).end();
        }

        res.setHeader('Content-Type', imageResult.rows[0].mime_type);
        res.setHeader('Cache-Control', 'no-store');
        return res.send(imageResult.rows[0].image_data);
    } catch (error) {
        console.error('Failed to load image:', error.message);
        return res.status(500).end();
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
    var usernameInput = getSafeString(req.body.username_input).trim();
    var username = usernameInput.includes('@') ? normalizeEmail(usernameInput) : usernameInput;
    var password = getSafeString(req.body.password_input);

    // Step 2: Check for empty fields
    if (username === '' || password === '') {
        currentUser = null;
        loginStatus = 'empty';
        return sendLoginPage(res);
    }

    // Reject malformed or oversized input before it reaches the database layer
    if (
        !isWithinMaxLength(username, MAX_EMAIL_LENGTH) ||
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

app.get('/my-posts-data', validateSession, async (req, res) => {
    try {
        const postsResult = await pool.query(`
            SELECT
                posts.post_id,
                COALESCE(NULLIF(users.display_name, ''), 'Unknown user') AS author_name,
                posts.created_at_display,
                posts.title,
                posts.content
            FROM posts
            LEFT JOIN users ON LOWER(users.username) = LOWER(posts.username)
            WHERE posts.username = $1
            ORDER BY posts.post_id
        `, [req.currentUser]);

        res.json(postsResult.rows.map(buildPostFromRow));
    } catch (error) {
        console.error('Failed to load user posts:', error.message);
        res.status(500).json([]);
    }
});

app.post('/signup', async function(req, res) {
    const displayNameInput = getSafeString(req.body.signup_username_input);
    const emailInput = getSafeString(req.body.signup_email_input);
    const password = getSafeString(req.body.signup_password_input);
    const passwordConfirmation = getSafeString(req.body.signup_password_confirm_input);
    const validation = validateSignupInput(displayNameInput, emailInput, password, passwordConfirmation);

    if (!validation.ok || !isWithinMaxLength(validation.email, MAX_EMAIL_LENGTH)) {
        return res.redirect('/?mode=signup&signup=' + encodeURIComponent(validation.code || 'invalid'));
    }

    try {
        const duplicateResult = await pool.query(
            'SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1',
            [validation.email]
        );

        if (duplicateResult.rows.length > 0) {
            return res.redirect('/?mode=signup&signup=duplicate');
        }

        const duplicateDisplayNameResult = await pool.query(
            'SELECT 1 FROM users WHERE LOWER(display_name) = LOWER($1) LIMIT 1',
            [validation.displayName]
        );

        if (duplicateDisplayNameResult.rows.length > 0) {
            return res.redirect('/?mode=signup&signup=duplicate_username');
        }

        const passwordHash = await hashPassword(password);
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
});

// Session Validation Middleware - Prevents Session Hijacking
async function validateSession(req, res, next) {
    const handleSessionFailure = async () => {
        res.clearCookie('session_id');

        // /ping is called via fetch, so return JSON + 401 for reliable client-side handling
        if (req.path === '/ping' || req.path === '/post-images-data' || req.path === '/my-posts-data') {
            return res.status(401).json({ status: 'session_invalid' });
        }

        if (req.path.startsWith('/post-images/')) {
            return res.status(401).end();
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
app.post('/makepost', validateSession, upload.array('image_files', MAX_IMAGES_PER_POST), async function(req, res) {
    try {
        let curDate = new Date();
        curDate = curDate.toLocaleString("en-GB");

        const submittedPostId = getSafeString(req.body.postId).trim();
        const parsedPostId = parsePostId(submittedPostId);
        const title = getSafeString(req.body.title_field).trim();
        const content = getSafeString(req.body.content_field).trim();

        if (
            title === '' ||
            content === '' ||
            (submittedPostId !== '' && parsedPostId === null) ||
            !isWithinMaxLength(title, MAX_POST_TITLE_LENGTH) ||
            !isWithinMaxLength(content, MAX_POST_CONTENT_LENGTH)
        ) {
            return res.status(400).send('Invalid post data.');
        }

        // This blog treats post fields as plain text, so reject HTML-significant input.
        if (containsHtmlLikeInput(title) || containsHtmlLikeInput(content)) {
            return res.status(400).send('Posts must use plain text only.');
        }

        const postId = parsedPostId ?? await getNextPostId();
        const uploadedFiles = Array.isArray(req.files) ? req.files : [];
        // Enforce per-post image limit before storing any new files
        const existingImageCountResult = await pool.query(
            'SELECT COUNT(*) AS count FROM post_images WHERE post_id = $1',
            [postId]
        );
        const existingImageCount = Number(existingImageCountResult.rows[0]?.count) || 0;

        if (existingImageCount + uploadedFiles.length > MAX_IMAGES_PER_POST) {
            return res.status(400).send(`You can upload up to ${MAX_IMAGES_PER_POST} images per post.`);
        }
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

        // Persist each uploaded image in the post_images table
        if (uploadedFiles.length > 0) {
            const startOrder = existingImageCount;

            for (let i = 0; i < uploadedFiles.length; i += 1) {
                const file = uploadedFiles[i];
                await pool.query(
                    `INSERT INTO post_images (post_id, filename, mime_type, size_bytes, image_data, sort_order)
                     VALUES ($1, $2, $3, $4, $5, $6)`,
                    [
                        postId,
                        file.originalname || null,
                        file.mimetype,
                        file.size,
                        file.buffer,
                        startOrder + i
                    ]
                );
            }
        }

        res.sendFile(__dirname + "/public/html/my_posts.html");
    } catch (error) {
        console.error('Failed to save encrypted post:', error.message);
        res.status(500).send('Unable to save post.');
    }
 });

 // Delete a post POST request
 app.post('/deletepost', validateSession, async (req, res) => {
    try {
        const submittedPostId = getSafeString(req.body.postId).trim();
        const postId = parsePostId(submittedPostId);

        if (postId === null) {
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

// Allow the post owner to remove a single image
app.post('/deleteimage', validateSession, async (req, res) => {
    try {
        const imageId = Number.parseInt(getSafeString(req.body.imageId).trim(), 10);

        if (!Number.isFinite(imageId)) {
            return res.status(400).json({ ok: false });
        }

        const deleteResult = await pool.query(
            `DELETE FROM post_images
             USING posts
             WHERE post_images.image_id = $1
               AND post_images.post_id = posts.post_id
               AND posts.username = $2
             RETURNING post_images.image_id`,
            [imageId, req.currentUser]
        );

        if (deleteResult.rowCount === 0) {
            return res.status(403).json({ ok: false });
        }

        return res.json({ ok: true });
    } catch (error) {
        console.error('Failed to delete image:', error.message);
        return res.status(500).json({ ok: false });
    }
});

// Friendly upload error messages for invalid files or limits
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        return res.status(400).send('Image upload failed. Please check file size and count.');
    }

    if (err && err.code === 'INVALID_IMAGE_TYPE') {
        return res.status(400).send('Only PNG, JPG, or WEBP images are allowed.');
    }

    return next(err);
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
