/**
 * Verifies the password hashing helper stores salted bcrypt hashes and validates passwords correctly.
 */
const assert = require('assert');
const {
    hashPassword,
    verifyPassword,
    looksLikeBcryptHash
} = require('../app/security/passwordHashing');

async function run() {
    const plainPassword = 'correct horse battery staple';

    // Hash the same password twice to confirm bcrypt uses a different salt each time.
    const firstHash = await hashPassword(plainPassword);
    const secondHash = await hashPassword(plainPassword);

    // The stored value should be a bcrypt hash, not the original password.
    assert.strictEqual(typeof firstHash, 'string');
    assert.notStrictEqual(firstHash, plainPassword);
    assert.strictEqual(looksLikeBcryptHash(firstHash), true);

    // Verification should accept the right password and reject the wrong one.
    assert.strictEqual(await verifyPassword(plainPassword, firstHash), true);
    assert.strictEqual(await verifyPassword('wrong password', firstHash), false);
    assert.notStrictEqual(firstHash, secondHash);

    console.log('Password hashing tests passed.');
}

run().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
