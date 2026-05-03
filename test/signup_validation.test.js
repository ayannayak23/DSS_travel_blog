const assert = require('assert');
const {
    normalizeEmail,
    normalizeDisplayName,
    isValidDisplayName,
    getPasswordRuleStatus,
    validateSignupInput
} = require('../app/security/signupValidation');

const validPassword = 'StrongPass1!';

assert.deepStrictEqual(getPasswordRuleStatus(validPassword), {
    lowercase: true,
    uppercase: true,
    number: true,
    minLength: true,
    special: true
});

assert.strictEqual(getPasswordRuleStatus('PASSWORD1!').lowercase, false);
assert.strictEqual(getPasswordRuleStatus('password1!').uppercase, false);
assert.strictEqual(getPasswordRuleStatus('Password!').number, false);
assert.strictEqual(getPasswordRuleStatus('Pass1!').minLength, false);
assert.strictEqual(getPasswordRuleStatus('Password1').special, false);
assert.strictEqual(isValidDisplayName('Travel_User1'), true);
assert.strictEqual(isValidDisplayName('ab'), false);
assert.strictEqual(isValidDisplayName('bad name'), false);
assert.strictEqual(isValidDisplayName('bad-name'), false);

assert.strictEqual(
    validateSignupInput('Travel_User1', 'test@example.com', validPassword, 'Different1!').code,
    'password_mismatch'
);

assert.strictEqual(normalizeEmail('  Test.User@Example.COM  '), 'test.user@example.com');
assert.strictEqual(normalizeDisplayName('  Travel_User1  '), 'Travel_User1');
assert.strictEqual(validateSignupInput('Travel_User1', 'test@example.com', validPassword, validPassword).ok, true);

console.log('Signup validation tests passed.');
