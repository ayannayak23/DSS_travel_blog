const { LIMITS, PATTERNS } = require('./config');
const { getRequestIp, getUserAgent } = require('./utils');

// Session management
function createSessionTools({ pool, getOidcUsername }) {
    // Check if the request is authenticated via OIDC (Auth0).
    function isOidcAuthenticated(req) {
        return Boolean(req.oidc && typeof req.oidc.isAuthenticated === 'function' && req.oidc.isAuthenticated());
    }

    // Validate the session ID format.
    function isValidSessionId(sessionId) {
        return typeof sessionId === 'string' && PATTERNS.sessionId.test(sessionId);
    }

    // Deactivate the session when the user logs out or the session becomes invalid to prevent session hijacking.
    async function deactivateSessionById(sessionId) {
        return pool.query('UPDATE sessions SET is_active = false WHERE session_id = $1', [sessionId]);
    }

    // Handle session validation failures by clearing the cookie.
    function handleSessionFailure(req, res) {
        res.clearCookie('session_id');

        if (req.path === '/ping' || req.path === '/post-images-data' || req.path === '/my-posts-data' || req.path === '/posts-data') {
            return res.status(401).json({ status: 'session_invalid' });
        }

        if (req.path.startsWith('/post-images/')) {
            return res.status(401).end();
        }

        return res.redirect('/');
    }

    // Middleware to validate the session on protected routes.
    async function validateSession(req, res, next) {
        if (isOidcAuthenticated(req)) {
            req.currentUser = getOidcUsername(req.oidc.user);
            req.session = {
                username: req.currentUser,
                authProvider: 'auth0'
            };
            return next();
        }

        const sessionId = req.cookies.session_id;
        const currentIp = getRequestIp(req);
        const currentUserAgent = getUserAgent(req);

        if (!sessionId) {
            console.warn('No session cookie found');
            return handleSessionFailure(req, res);
        }

        if (!isValidSessionId(sessionId)) {
            console.warn('Malformed session cookie received');
            return handleSessionFailure(req, res);
        }

        try {
            const sessionResult = await pool.query(
                `SELECT *, EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - last_activity)) / 60 AS minutes_elapsed
                 FROM sessions
                 WHERE session_id = $1 AND is_active = true`,
                [sessionId]
            );

            // If no active session is found, treat it as invalid.
            if (sessionResult.rows.length === 0) {
                console.warn('Session not found or inactive:', sessionId);
                return handleSessionFailure(req, res);
            }

            const session = sessionResult.rows[0];
            const minutesElapsed = Number(session.minutes_elapsed);

            // Check for session timeout to prevent session hijacking.
            if (!Number.isFinite(minutesElapsed) || minutesElapsed > LIMITS.sessionTimeoutMinutes) {
                console.warn('Session timeout for user:', session.username);
                await deactivateSessionById(sessionId);
                return handleSessionFailure(req, res);
            }

            // Compare the stored IP address and user-agent with the current request to detect session hijacking.
            if (session.ip_address !== currentIp) {
                console.warn('IP mismatch detected for session:', sessionId);
                console.warn('Original IP:', session.ip_address, 'Current IP:', currentIp);
                await deactivateSessionById(sessionId);
                return handleSessionFailure(req, res);
            }

            if (session.user_agent !== currentUserAgent) {
                console.warn('User-agent mismatch detected for session:', sessionId);
                console.warn('Original user-agent:', session.user_agent);
                console.warn('Current user-agent:', currentUserAgent);
                await deactivateSessionById(sessionId);
                return handleSessionFailure(req, res);
            }

            // Update last activity timestamp to extend session validity for session hijacking prevention.
            await pool.query(
                'UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = $1',
                [sessionId]
            );

            req.session = session;
            req.currentUser = session.username;
            return next();
        } catch (error) {
            console.error('Session validation error:', error.message);
            return handleSessionFailure(req, res);
        }
    }

    return {
        validateSession,
        isValidSessionId,
        deactivateSessionById
    };
}

module.exports = {
    createSessionTools
};
