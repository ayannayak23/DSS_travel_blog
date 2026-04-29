const bcrypt = require('bcryptjs');

const BCRYPT_COST_FACTOR = 12;
const BCRYPT_HASH_PATTERN = /^\$2[aby]\$\d{2}\$/;

function looksLikeBcryptHash(value) {
    return typeof value === 'string' && BCRYPT_HASH_PATTERN.test(value);
}

async function hashPassword(plainPassword) {
    if (typeof plainPassword !== 'string' || plainPassword.length === 0) {
        throw new Error('Password must be a non-empty string.');
    }

    // bcrypt creates a unique salt for each password and stores it inside the hash.
    return bcrypt.hash(plainPassword, BCRYPT_COST_FACTOR);
}

async function verifyPassword(plainPassword, storedHash) {
    if (typeof plainPassword !== 'string' || !looksLikeBcryptHash(storedHash)) {
        return false;
    }

    try {
        return await bcrypt.compare(plainPassword, storedHash);
    } catch {
        return false;
    }
}

module.exports = {
    BCRYPT_COST_FACTOR,
    hashPassword,
    verifyPassword,
    looksLikeBcryptHash
};
