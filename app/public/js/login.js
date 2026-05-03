let recaptchaSiteKey = null;
let isRecaptchaApiLoaded = false;
let isRecaptchaRendered = false;

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const displayNamePattern = /^[A-Za-z0-9_]{3,20}$/;
const specialCharacterPattern = /[!@#$%^&*(),.?":{}|<>_\-+=~`[\]\\;/']/;

// Callback used by the reCAPTCHA API script in login.html
window.onRecaptchaLoaded = function() {
    isRecaptchaApiLoaded = true;
    renderRecaptchaIfReady();
};

function renderRecaptchaIfReady() {
    // Render only once script and site key are ready
    if (!isRecaptchaApiLoaded || !recaptchaSiteKey || isRecaptchaRendered) {
        return;
    }

    if (typeof grecaptcha === 'undefined') {
        return;
    }

    grecaptcha.render('recaptcha_container', {
        sitekey: recaptchaSiteKey
    });
    isRecaptchaRendered = true;
}

async function setupRecaptcha() {
    try {
        const response = await fetch('/captcha-config', { cache: 'no-store' });
        const configData = await response.json();
        recaptchaSiteKey = configData.siteKey || null;

        if (typeof grecaptcha !== 'undefined' && typeof grecaptcha.render === 'function') {
            isRecaptchaApiLoaded = true;
        }

        renderRecaptchaIfReady();
    } catch (error) {
        console.error('Failed to load reCAPTCHA config:', error);
    }
}

function setMessage(element, message, type) {
    if (!element) {
        return;
    }

    element.textContent = message || '';
    element.classList.remove('error', 'success');

    if (type) {
        element.classList.add(type);
    }
}

function getPasswordRules(password) {
    return {
        lowercase: /[a-z]/.test(password),
        uppercase: /[A-Z]/.test(password),
        number: /[0-9]/.test(password),
        minLength: password.length >= 8,
        special: specialCharacterPattern.test(password)
    };
}

function allRulesPass(rules) {
    return Object.values(rules).every(Boolean);
}

function updatePasswordChecklist() {
    const passwordInput = document.getElementById('signup_password_input');
    const confirmInput = document.getElementById('signup_password_confirm_input');
    const usernameInput = document.getElementById('signup_username_input');
    const emailInput = document.getElementById('signup_email_input');
    const signupButton = document.getElementById('signup_btn');
    const signupMessage = document.getElementById('signup_message');

    if (!passwordInput || !confirmInput || !usernameInput || !emailInput || !signupButton) {
        return;
    }

    const rules = getPasswordRules(passwordInput.value);

    for (const [ruleName, passed] of Object.entries(rules)) {
        const item = document.querySelector(`[data-rule="${ruleName}"]`);
        if (!item) {
            continue;
        }

        item.classList.toggle('rule-met', passed);
        item.querySelector('span').textContent = passed ? 'OK' : 'X';
    }

    const usernameIsValid = displayNamePattern.test(usernameInput.value.trim());
    const emailIsValid = emailPattern.test(emailInput.value.trim().toLowerCase());
    const passwordsMatch = passwordInput.value === confirmInput.value;
    const formIsValid = usernameIsValid && emailIsValid && allRulesPass(rules) && passwordsMatch;

    signupButton.disabled = !formIsValid;

    if (usernameInput.value !== '' && !usernameIsValid) {
        setMessage(signupMessage, 'Username must be 3 to 20 letters, numbers, or underscores.', 'error');
    } else if (confirmInput.value !== '' && !passwordsMatch) {
        setMessage(signupMessage, 'Passwords do not match.', 'error');
    } else if (emailInput.value !== '' && !emailIsValid) {
        setMessage(signupMessage, 'Please enter a valid email address.', 'error');
    } else {
        setMessage(signupMessage, '', null);
    }
}

function setAuthMode(mode) {
    const loginPanel = document.getElementById('login_panel');
    const signupPanel = document.getElementById('signup_panel');
    const loginTab = document.getElementById('login_tab');
    const signupTab = document.getElementById('signup_tab');
    const isSignup = mode === 'signup';

    loginPanel.hidden = isSignup;
    signupPanel.hidden = !isSignup;
    loginTab.classList.toggle('active', !isSignup);
    signupTab.classList.toggle('active', isSignup);
    loginTab.setAttribute('aria-selected', String(!isSignup));
    signupTab.setAttribute('aria-selected', String(isSignup));
}

function showSignupRedirectMessage() {
    const params = new URLSearchParams(window.location.search);
    const signupStatus = params.get('signup');
    const loginMessage = document.getElementById('login_message');
    const signupMessage = document.getElementById('signup_message');

    const messages = {
        created: ['Account created. Please log in.', 'success'],
        invalid_username: ['Username must be 3 to 20 letters, numbers, or underscores.', 'error'],
        invalid_email: ['Please enter a valid email address.', 'error'],
        weak_password: ['Password must satisfy all listed rules.', 'error'],
        password_mismatch: ['Passwords do not match.', 'error'],
        duplicate: ['An account with that email already exists.', 'error'],
        duplicate_username: ['That username is already taken.', 'error'],
        server_error: ['Sign-up is unavailable. Please try again later.', 'error']
    };

    if (!signupStatus || !messages[signupStatus]) {
        return;
    }

    const [message, type] = messages[signupStatus];
    if (signupStatus === 'created') {
        setMessage(loginMessage, message, type);
        return;
    }

    setMessage(signupMessage, message, type);
}

async function checkLoginAttempts() {
    const response = await fetch('/login-status', { cache: 'no-store' });
    const statusData = await response.json();
    const loginMessage = document.getElementById('login_message');

    if (loginMessage && loginMessage.classList.contains('success')) {
        return;
    }

    const messages = {
        empty: 'Please fill out the login fields.',
        captcha_required: 'Please complete the reCAPTCHA check.',
        captcha_failed: 'reCAPTCHA verification failed. Please try again.',
        invalid: 'Invalid email or password.',
        server_error: 'Login service unavailable. Please try again later.'
    };

    if (statusData.status === 'first_load' || statusData.status === 'success') {
        return;
    }

    if (messages[statusData.status]) {
        setMessage(loginMessage, messages[statusData.status], 'error');
    }
}

function setupAuthUi() {
    const params = new URLSearchParams(window.location.search);
    setAuthMode(params.get('mode') === 'signup' ? 'signup' : 'login');

    document.getElementById('login_tab').addEventListener('click', () => setAuthMode('login'));
    document.getElementById('signup_tab').addEventListener('click', () => setAuthMode('signup'));

    const signupForm = document.getElementById('signup_form');
    const signupInputs = [
        document.getElementById('signup_username_input'),
        document.getElementById('signup_email_input'),
        document.getElementById('signup_password_input'),
        document.getElementById('signup_password_confirm_input')
    ];

    for (const input of signupInputs) {
        input.addEventListener('input', updatePasswordChecklist);
    }

    signupForm.addEventListener('submit', (event) => {
        updatePasswordChecklist();
        if (document.getElementById('signup_btn').disabled) {
            event.preventDefault();
            setMessage(document.getElementById('signup_message'), 'Please fix the highlighted sign-up requirements.', 'error');
        }
    });

    updatePasswordChecklist();
    showSignupRedirectMessage();
}

setupAuthUi();
setupRecaptcha();
checkLoginAttempts();
