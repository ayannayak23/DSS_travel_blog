/**
 * To verify server-side sign up validation matches the login page checklist and display name rules.
 */
const assert = require('assert');
const {
    normalizeEmail,
    normalizeDisplayName,
    isValidDisplayName,
    getPasswordRuleStatus,
    validateSignupInput
} = require('../app/security/signupValidation');

const validPassword = 'StrongPass1!';

describe('signup validation', function () {
    it('accepts a password that meets every checklist rule', function () {
        // To ensure a valid password satisfies every checklist rule shown on the sign-up form.
        assert.deepStrictEqual(getPasswordRuleStatus(validPassword), {
            lowercase: true,
            uppercase: true,
            number: true,
            minLength: true,
            special: true
        });
    });

    it('fails each password rule independently when needed', function () {
        // To verify each password rule fails independently when its requirement is missing.
        assert.strictEqual(getPasswordRuleStatus('PASSWORD1!').lowercase, false);
        assert.strictEqual(getPasswordRuleStatus('password1!').uppercase, false);
        assert.strictEqual(getPasswordRuleStatus('Password!').number, false);
        assert.strictEqual(getPasswordRuleStatus('Pass1!').minLength, false);
        assert.strictEqual(getPasswordRuleStatus('Password1').special, false);
    });

    it('accepts only simple safe display names', function () {
        // To ensure display names are public author labels, so they stay simple and predictable.
        assert.strictEqual(isValidDisplayName('Travel_User1'), true);
        assert.strictEqual(isValidDisplayName('ab'), false);
        assert.strictEqual(isValidDisplayName('bad name'), false);
        assert.strictEqual(isValidDisplayName('bad-name'), false);
    });

    it('requires password confirmation to match', function () {
        // To ensure password confirmation must match before the route can create the account.
        assert.strictEqual(
            validateSignupInput('Travel_User1', 'test@example.com', validPassword, 'Different1!').code,
            'password_mismatch'
        );
    });

    it('normalizes input and accepts a fully valid sign-up payload', function () {
        // To ensure normalisation and the full valid path are checked together for route compatibility.
        assert.strictEqual(normalizeEmail('  Test.User@Example.COM  '), 'test.user@example.com');
        assert.strictEqual(normalizeDisplayName('  Travel_User1  '), 'Travel_User1');
        assert.strictEqual(validateSignupInput('Travel_User1', 'test@example.com', validPassword, validPassword).ok, true);
    });
});
