/**
 * To centralises server-side sign-up validation for email, display name, and password rules.
 * Frontend validation improves usability, but this helper enforces the same rules before database writes.
 */
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SPECIAL_CHARACTER_PATTERN = /[!@#$%^&*(),.?":{}|<>_\-+=~`[\]\\;/']/;
const DISPLAY_NAME_PATTERN = /^[A-Za-z0-9_]{3,20}$/;
const MAX_EMAIL_LENGTH = 254;

// To normalise email addresses before duplicate checks and login storage.
function normalizeEmail(email) {
    return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

// To keep display names case-preserving while removing accidental surrounding spaces.
function normalizeDisplayName(displayName) {
    return typeof displayName === 'string' ? displayName.trim() : '';
}

// To ensure public display names are limited to simple characters for predictable author rendering.
function isValidDisplayName(displayName) {
    return DISPLAY_NAME_PATTERN.test(normalizeDisplayName(displayName));
}

// To validate normalised email input before it is used in the users table.
function isValidEmail(email) {
    const normalisedEmail = normalizeEmail(email);
    return normalisedEmail.length > 0 &&
        normalisedEmail.length <= MAX_EMAIL_LENGTH &&
        EMAIL_PATTERN.test(normalisedEmail);
}

// To match the password checklist shown in the sign-up form.
function getPasswordRuleStatus(password) {
    const value = typeof password === 'string' ? password : '';

    return {
        lowercase: /[a-z]/.test(value),
        uppercase: /[A-Z]/.test(value),
        number: /[0-9]/.test(value),
        minLength: value.length >= 8,
        special: SPECIAL_CHARACTER_PATTERN.test(value)
    };
}

// To require every password checklist rule to pass before accepting sign-up.
function isValidPassword(password) {
    const rules = getPasswordRuleStatus(password);
    return Object.values(rules).every(Boolean);
}

// To return clear validation results that the sign-up route can map to user-facing messages.
function validateSignupInput(displayName, email, password, passwordConfirmation) {
    const normalisedDisplayName = normalizeDisplayName(displayName);
    const normalisedEmail = normalizeEmail(email);
    const plainPassword = typeof password === 'string' ? password : '';
    const confirmedPassword = typeof passwordConfirmation === 'string' ? passwordConfirmation : '';

    // To check each field against the rules and return the first error encountered, or success if all pass.
    if (!isValidDisplayName(normalisedDisplayName)) {
        return {
            ok: false,
            code: 'invalid_username',
            displayName: normalisedDisplayName,
            email: normalisedEmail
        };
    }

    if (!isValidEmail(normalisedEmail)) {
        return {
            ok: false,
            code: 'invalid_email',
            displayName: normalisedDisplayName,
            email: normalisedEmail
        };
    }

    if (!isValidPassword(plainPassword)) {
        return {
            ok: false,
            code: 'weak_password',
            displayName: normalisedDisplayName,
            email: normalisedEmail
        };
    }

    // To require the user to enter the same password twice to prevent typos.
    if (plainPassword !== confirmedPassword) {
        return {
            ok: false,
            code: 'password_mismatch',
            displayName: normalisedDisplayName,
            email: normalisedEmail
        };
    }

    return {
        ok: true,
        displayName: normalisedDisplayName,
        email: normalisedEmail
    };
}

// To centralises server-side sign-up validation for email, display name, and password rules.
module.exports = {
    MAX_EMAIL_LENGTH,
    normalizeEmail,
    normalizeDisplayName,
    isValidDisplayName,
    isValidEmail,
    getPasswordRuleStatus,
    isValidPassword,
    validateSignupInput
};
