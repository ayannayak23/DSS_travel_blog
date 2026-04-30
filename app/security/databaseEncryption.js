const crypto = require('crypto');

const ENCRYPTION_PREFIX = 'enc:v1:';
const KEY_PATTERN = /^[a-f0-9]{64}$/i;
const IV_LENGTH_BYTES = 12;
const AUTH_TAG_LENGTH_BYTES = 16;

function getEncryptionKey() {
    const keyHex = process.env.DATABASE_ENCRYPTION_KEY;

    if (!KEY_PATTERN.test(keyHex || '')) {
        throw new Error('DATABASE_ENCRYPTION_KEY must be a 64-character hex string.');
    }

    return Buffer.from(keyHex, 'hex');
}

function isEncryptedValue(value) {
    return typeof value === 'string' && value.startsWith(ENCRYPTION_PREFIX);
}

function encryptForDatabase(plainText) {
    if (plainText === null || plainText === undefined || plainText === '') {
        return plainText ?? null;
    }

    const iv = crypto.randomBytes(IV_LENGTH_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
    const ciphertext = Buffer.concat([
        cipher.update(String(plainText), 'utf8'),
        cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    return [
        'enc',
        'v1',
        iv.toString('hex'),
        authTag.toString('hex'),
        ciphertext.toString('hex')
    ].join(':');
}

function decryptFromDatabase(storedValue) {
    if (storedValue === null || storedValue === undefined || storedValue === '') {
        return storedValue ?? null;
    }

    if (!isEncryptedValue(storedValue)) {
        return storedValue;
    }

    const parts = storedValue.split(':');
    if (parts.length !== 5 || parts[0] !== 'enc' || parts[1] !== 'v1') {
        throw new Error('Invalid encrypted database value format.');
    }

    const [, , ivHex, authTagHex, ciphertextHex] = parts;

    if (
        ivHex.length !== IV_LENGTH_BYTES * 2 ||
        authTagHex.length !== AUTH_TAG_LENGTH_BYTES * 2 ||
        ciphertextHex.length === 0
    ) {
        throw new Error('Invalid encrypted database value format.');
    }

    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        getEncryptionKey(),
        Buffer.from(ivHex, 'hex')
    );
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

    const plaintext = Buffer.concat([
        decipher.update(Buffer.from(ciphertextHex, 'hex')),
        decipher.final()
    ]);

    return plaintext.toString('utf8');
}

module.exports = {
    ENCRYPTION_PREFIX,
    encryptForDatabase,
    decryptFromDatabase,
    isEncryptedValue
};
