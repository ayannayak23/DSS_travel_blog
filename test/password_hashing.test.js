/**
 * To verify the password hashing helper stores peppered bcrypt hashes and validates passwords correctly. peppereing
 */
const assert = require('assert');
const bcrypt = require('bcryptjs');

process.env.PASSWORD_PEPPER = 'test-only-password-pepper-for-hashing-tests';

const {
    hashPassword,
    verifyPassword,
    looksLikeBcryptHash
} = require('../app/security/passwordHashing');

async function run() {
    const plainPassword = 'correct horse battery staple';
    const originalPepper = process.env.PASSWORD_PEPPER;


    // To hash the same password twice to confirm bcrypt still uses a different salt each time.
    const firstHash = await hashPassword(plainPassword);
    const secondHash = await hashPassword(plainPassword);

    // To ensure the stored value is a bcrypt hash, not the original password or peppered input.
    assert.strictEqual(typeof firstHash, 'string');
    assert.notStrictEqual(firstHash, plainPassword);
    assert.strictEqual(looksLikeBcryptHash(firstHash), true);

    // To verify the right password is accepted and the wrong one is rejected when the pepper matches.
    assert.strictEqual(await verifyPassword(plainPassword, firstHash), true);
    assert.strictEqual(await verifyPassword('wrong password', firstHash), false);
    assert.notStrictEqual(firstHash, secondHash);

    // To change the server-side pepper should prevent the same password from verifying.
    process.env.PASSWORD_PEPPER = 'different-test-only-password-pepper';
    assert.strictEqual(await verifyPassword(plainPassword, firstHash), false);
    process.env.PASSWORD_PEPPER = originalPepper;

    // To ensure old hashes made directly from the raw password do not verify through the peppered flow.
    const oldUnpepperedHash = await bcrypt.hash(plainPassword, 4);
    assert.strictEqual(looksLikeBcryptHash(oldUnpepperedHash), true);
    assert.strictEqual(await verifyPassword(plainPassword, oldUnpepperedHash), false);

    // To ensure missing pepper configuration fails clearly instead of silently hashing without a pepper.
    delete process.env.PASSWORD_PEPPER;
    await assert.rejects(
        () => hashPassword(plainPassword),
    );
    await assert.rejects(
        () => verifyPassword(plainPassword, firstHash),
    );
    process.env.PASSWORD_PEPPER = originalPepper;

    console.log('Password hashing tests passed.');
}

run().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});