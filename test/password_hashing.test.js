/**
 * To verify the password hashing helper stores peppered bcrypt hashes and validates passwords correctly. 
 */
const assert = require('assert');
const bcrypt = require('bcryptjs');

const TEST_PASSWORD_PEPPER = 'd8dacde546e09c4c9963a97d99777c8c4ee81f94a28e854a0281d9608a964261';

const {
    hashPassword,
    verifyPassword,
    looksLikeBcryptHash
} = require('../app/security/passwordHashing');

describe('password hashing', function () {
    const plainPassword = 'correct horse battery staple';
    const originalPepper = process.env.PASSWORD_PEPPER;

    beforeEach(function () {
        process.env.PASSWORD_PEPPER = TEST_PASSWORD_PEPPER;
    });

    after(function () {
        if (typeof originalPepper === 'string') {
            process.env.PASSWORD_PEPPER = originalPepper;
        } else {
            delete process.env.PASSWORD_PEPPER;
        }
    });

    it('hashes and verifies peppered bcrypt passwords', async function () {
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
    });

    it('fails verification when the server pepper changes', async function () {
        const firstHash = await hashPassword(plainPassword);

        // To change the server side pepper should prevent the same password from verifying.
        process.env.PASSWORD_PEPPER = 'different-test-only-password-pepper';
        assert.strictEqual(await verifyPassword(plainPassword, firstHash), false);
    });

    it('does not accept legacy unpeppered hashes', async function () {
        // To ensure old hashes made directly from the raw password do not verify through the peppered flow.
        const oldUnpepperedHash = await bcrypt.hash(plainPassword, 4);
        assert.strictEqual(looksLikeBcryptHash(oldUnpepperedHash), true);
        assert.strictEqual(await verifyPassword(plainPassword, oldUnpepperedHash), false);
    });

    it('fails clearly when the pepper is missing', async function () {
        const firstHash = await hashPasswordWithRestoredPepper(plainPassword);
        delete process.env.PASSWORD_PEPPER;
        await assert.rejects(() => hashPassword(plainPassword));
        await assert.rejects(() => verifyPassword(plainPassword, firstHash));
    });
});

async function hashPasswordWithRestoredPepper(plainPassword) {
    process.env.PASSWORD_PEPPER = TEST_PASSWORD_PEPPER;
    return hashPassword(plainPassword);
}
