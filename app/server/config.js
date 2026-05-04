const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const PORT = 3000;

const APP_ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(APP_ROOT, 'public');
const HTML_DIR = path.join(PUBLIC_DIR, 'html');

const ENV = {
    dbConnectionString: process.env.DATABASE_URL,
    recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY,
    recaptchaSecretKey: process.env.RECAPTCHA_SECRET_KEY,
    auth0Secret: process.env.AUTH0_SECRET,
    auth0BaseURL: process.env.AUTH0_BASE_URL,
    auth0ClientID: process.env.AUTH0_CLIENT_ID,
    auth0IssuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL
};

const LIMITS = {
    sessionTimeoutMinutes: 4,
    maxPasswordLength: 256,
    maxEmailLength: 254,
    maxRecaptchaTokenLength: 4096,
    maxPostIdLength: 32,
    maxPostTitleLength: 120,
    maxPostContentLength: 5000,
    maxImagesPerPost: 5,
    maxImageSizeBytes: 2 * 1024 * 1024
};

const PATTERNS = {
    displayName: /^[A-Za-z0-9_]{3,20}$/,
    sessionId: /^[a-f0-9]{64}$/i,
    numericOnly: /^[0-9]+$/,
    plainTextOnly: /[<>]/
};

const ALLOWED_IMAGE_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);

const OAUTH_CONNECTIONS = {
    google: 'google-oauth2',
    github: 'github'
};

const PATHS = {
    publicDir: PUBLIC_DIR,
    loginPage: path.join(HTML_DIR, 'login.html'),
    indexPage: path.join(HTML_DIR, 'index.html'),
    myPostsPage: path.join(HTML_DIR, 'my_posts.html')
};

const SESSION_COOKIE_OPTIONS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000
};

function assertRequiredConfig() {
    if (!ENV.dbConnectionString) {
        console.error('Missing DATABASE_URL in app/.env.');
        process.exit(1);
    }

    if (!ENV.recaptchaSiteKey || !ENV.recaptchaSecretKey) {
        console.error('Missing RECAPTCHA_SITE_KEY or RECAPTCHA_SECRET_KEY in app/.env.');
        process.exit(1);
    }
}

module.exports = {
    PORT,
    ENV,
    LIMITS,
    PATTERNS,
    PATHS,
    ALLOWED_IMAGE_MIME_TYPES,
    OAUTH_CONNECTIONS,
    SESSION_COOKIE_OPTIONS,
    assertRequiredConfig
};
