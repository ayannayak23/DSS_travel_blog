/**
 * To verify database encryption helpers encrypt, decrypt, and reject tampered ciphertext.
 */
const assert = require('assert');

// Use a fixed test only key so encryption behaviour can be checked without reading real secrets.
process.env.DATABASE_ENCRYPTION_KEY = 'd8dacde546e09c4c9963a97d99777c8c4ee81f94a28e854a0281d9608a96426a';

const {
    encryptForDatabase,
    decryptFromDatabase,
    isEncryptedValue
} = require('../app/security/databaseEncryption');

// To change one ciphertext character to prove AES-GCM authentication detects tampering.
function tamperWithLastCharacter(value) {
    const lastCharacter = value[value.length - 1];
    const replacement = lastCharacter === '0' ? '1' : '0';
    return value.slice(0, -1) + replacement;
}

const plainText = 'This post body should be encrypted in PostgreSQL.';
const firstEncrypted = encryptForDatabase(plainText);
const secondEncrypted = encryptForDatabase(plainText);

// To ensure encrypted database values do not expose plaintext and decrypt back to the original content.
assert.notStrictEqual(firstEncrypted, plainText);
assert.strictEqual(decryptFromDatabase(firstEncrypted), plainText);

// A fresh IV should produce different ciphertext for the same plaintext.
assert.notStrictEqual(firstEncrypted, secondEncrypted);
assert.strictEqual(isEncryptedValue(firstEncrypted), true);
assert.strictEqual(isEncryptedValue(plainText), false);

// To ensure legacy plaintext remains readable, while modified encrypted values fail authentication.
assert.strictEqual(decryptFromDatabase(plainText), plainText);
assert.throws(() => decryptFromDatabase(tamperWithLastCharacter(firstEncrypted)));

console.log('Database encryption tests passed.');
