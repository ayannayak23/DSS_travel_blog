/**
 * Verifies database encryption helpers encrypt, decrypt, and reject tampered ciphertext.
 */
const assert = require('assert');

// Use a fixed test-only key so encryption behaviour can be checked without reading real secrets.
process.env.DATABASE_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const {
    encryptForDatabase,
    decryptFromDatabase,
    isEncryptedValue
} = require('../app/security/databaseEncryption');

// Change one ciphertext character to prove AES-GCM authentication detects tampering.
function tamperWithLastCharacter(value) {
    const lastCharacter = value[value.length - 1];
    const replacement = lastCharacter === '0' ? '1' : '0';
    return value.slice(0, -1) + replacement;
}

const plainText = 'This post body should be encrypted in PostgreSQL.';
const firstEncrypted = encryptForDatabase(plainText);
const secondEncrypted = encryptForDatabase(plainText);

// Encrypted database values should not expose plaintext and should decrypt back to the original content.
assert.notStrictEqual(firstEncrypted, plainText);
assert.strictEqual(decryptFromDatabase(firstEncrypted), plainText);

// A fresh IV should produce different ciphertext for the same plaintext.
assert.notStrictEqual(firstEncrypted, secondEncrypted);
assert.strictEqual(isEncryptedValue(firstEncrypted), true);
assert.strictEqual(isEncryptedValue(plainText), false);

// Legacy plaintext remains readable, while modified encrypted values fail authentication.
assert.strictEqual(decryptFromDatabase(plainText), plainText);
assert.throws(() => decryptFromDatabase(tamperWithLastCharacter(firstEncrypted)));

console.log('Database encryption tests passed.');
