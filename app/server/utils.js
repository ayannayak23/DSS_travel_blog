function getSafeString(value) {
    return typeof value === 'string' ? value : '';
}

function isWithinMaxLength(value, maxLength) {
    return typeof value === 'string' && value.length <= maxLength;
}

// Basic HTML entity decoding for a limited set of entities to prevent XSS when displaying user-generated content.
const BASIC_HTML_ENTITY_MAP = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    '#39': '\''
};

function decodeBasicHtmlEntities(value) {
    return getSafeString(value).replace(/&(amp|lt|gt|quot|#39);/g, (match, entity) => BASIC_HTML_ENTITY_MAP[entity] || match);
}

function sanitizeHtmlText(value) {
    return decodeBasicHtmlEntities(value).replace(/[&<>"']/g, (character) => {
        switch (character) {
        case '&':
            return '&amp;';
        case '<':
            return '&lt;';
        case '>':
            return '&gt;';
        case '"':
            return '&quot;';
        case '\'':
            return '&#39;';
        default:
            return character;
        }
    });
}

function getRequestIp(req) {
    return req.ip || req.connection.remoteAddress;
}

function getUserAgent(req) {
    return req.get('user-agent') || '';
}

function sendPage(res, filePath) {
    return res.sendFile(filePath, (error) => {
        if (error) {
            console.log(error);
        }
    });
}

module.exports = {
    getSafeString,
    isWithinMaxLength,
    decodeBasicHtmlEntities,
    sanitizeHtmlText,
    getRequestIp,
    getUserAgent,
    sendPage
};
