function createSecurityHeadersMiddleware() {
    return (req, res, next) => {
        res.setHeader(
            'Content-Security-Policy',
            [
                "default-src 'self'",
                "script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/",
                "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
                "font-src 'self' https://cdnjs.cloudflare.com",
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
    };
}

module.exports = {
    createSecurityHeadersMiddleware
};
