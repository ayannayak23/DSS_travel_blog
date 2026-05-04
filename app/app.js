const express = require('express');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const { auth } = require('express-openid-connect');
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

app.disable('x-powered-by');
app.use(auth(authModule.createAuth0Config()));
app.use(createSecurityHeadersMiddleware());
app.use(express.static(PATHS.publicDir));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

authModule.registerRoutes(app, sessionTools);
registerPostRoutes(app, {
    pool,
    validateSession: sessionTools.validateSession
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
