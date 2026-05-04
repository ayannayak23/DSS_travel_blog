/**
 * Provides bcrypt helpers for salted one-way password hashing and verification.
 * Plaintext passwords are never stored; only bcrypt hashes are saved in the users table.
 */
const bcrypt = require('bcryptjs');

const BCRYPT_COST_FACTOR = 12;
const BCRYPT_HASH_PATTERN = /^\$2[aby]\$\d{2}\$/;

// Accept only bcrypt-formatted stored values before attempting password verification.
function looksLikeBcryptHash(value) {
    return typeof value === 'string' && BCRYPT_HASH_PATTERN.test(value);
}

// Hash a submitted password; bcrypt creates and embeds a unique salt inside each hash.
async function hashPassword(plainPassword) {
    if (typeof plainPassword !== 'string' || plainPassword.length === 0) {
        throw new Error('Password must be a non-empty string.');
    }

    return bcrypt.hash(plainPassword, BCRYPT_COST_FACTOR);
}

// Compare a submitted password with the stored hash without recovering the original password.
async function verifyPassword(plainPassword, storedHash) {
    if (typeof plainPassword !== 'string' || !looksLikeBcryptHash(storedHash)) {
        return false;
    }

    try {
        return await bcrypt.compare(plainPassword, storedHash);
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
