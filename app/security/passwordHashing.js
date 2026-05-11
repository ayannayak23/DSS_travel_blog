/**
 * To provide peppered bcrypt helpers for one-way password hashing and verification.
 * The database stores only bcrypt hashes; the server-side pepper stays in the environment.
 */
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const BCRYPT_COST_FACTOR = 12;
const BCRYPT_HASH_PATTERN = /^\$2[aby]\$\d{2}\$/;

// To accept only bcrypt-formatted stored values before attempting password verification.
function looksLikeBcryptHash(value) {
    return typeof value === 'string' && BCRYPT_HASH_PATTERN.test(value);
}

function getPasswordPepper() {
    const pepper = process.env.PASSWORD_PEPPER;

    if (typeof pepper !== 'string' || pepper.trim().length === 0) {
        throw new Error('PASSWORD_PEPPER must be set before hashing or verifying passwords.');
    }

    return pepper;
}

// HMAC mixes the password with the server-side pepper before bcrypt adds its per-password salt.
function applyPasswordPepper(plainPassword) {
    return crypto
        .createHmac('sha256', getPasswordPepper())
        .update(plainPassword, 'utf8')
        .digest('hex');
}

// To hash a submitted password; bcrypt creates and embeds a unique salt inside each hash.
async function hashPassword(plainPassword) {
    if (typeof plainPassword !== 'string' || plainPassword.length === 0) {
        throw new Error('Password must be a non-empty string.');
    }

    return bcrypt.hash(applyPasswordPepper(plainPassword), BCRYPT_COST_FACTOR);
}

// To compare a submitted password with the stored hash without recovering the original password.
async function verifyPassword(plainPassword, storedHash) {
    if (typeof plainPassword !== 'string' || !looksLikeBcryptHash(storedHash)) {
        return false;
    }

    const pepperedPassword = applyPasswordPepper(plainPassword);

    try {
        return await bcrypt.compare(pepperedPassword, storedHash);
    } catch {
        // Malformed hashes or bcrypt failures are treated as failed authentication.
        return false;
    }
}

module.exports = {
    BCRYPT_COST_FACTOR,
    hashPassword,
    verifyPassword,
    looksLikeBcryptHash
};
