function getSafeString(value) {
    return typeof value === 'string' ? value : '';
}

function isWithinMaxLength(value, maxLength) {
    return typeof value === 'string' && value.length <= maxLength;
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
    getRequestIp,
    getUserAgent,
    sendPage
};
