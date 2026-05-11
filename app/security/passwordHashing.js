/**
 * TO provides the bcrypt helpers for salted one-way password hashing and verification.
 * The plaintext passwords are never stored, just the bcrypt hashes are saved in the users table.
 */
const bcrypt = require('bcryptjs');

const BCRYPT_COST_FACTOR = 12;
const BCRYPT_HASH_PATTERN = /^\$2[aby]\$\d{2}\$/;

// To accept only bcrypt-formatted stored values before attempting password verification.
function looksLikeBcryptHash(value) {
    return typeof value === 'string' && BCRYPT_HASH_PATTERN.test(value);
}

// To hash a submitted password; bcrypt creates and embeds a unique salt inside each hash.
async function hashPassword(plainPassword) {
    if (typeof plainPassword !== 'string' || plainPassword.length === 0) {
        throw new Error('Password must be a non-empty string.');
    }

    return bcrypt.hash(plainPassword, BCRYPT_COST_FACTOR);
}

// To compare a submitted password with the stored hash without recovering the original password.
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
// To upgrade the cost factor of existing hashes on login, if the hash was created with a lower cost.
module.exports = {
    BCRYPT_COST_FACTOR,
    hashPassword,
    verifyPassword,
    looksLikeBcryptHash
};
