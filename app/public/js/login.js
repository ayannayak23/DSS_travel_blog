let recaptchaSiteKey = null;
let isRecaptchaApiLoaded = false;
let isRecaptchaRendered = false;

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

    // Safety guard in case API object is not attached yet
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
        // Fetch the public reCAPTCHA site key from backend
        const response = await fetch('/captcha-config', { cache: 'no-store' });
        const configData = await response.json();
        recaptchaSiteKey = configData.siteKey || null;

        // Handle case where API script loaded before this fetch completed
        if (typeof grecaptcha !== 'undefined' && typeof grecaptcha.render === 'function') {
            isRecaptchaApiLoaded = true;
        }

        renderRecaptchaIfReady();
    } catch (error) {
        console.error('Failed to load reCAPTCHA config:', error);
    }
}

// Update error message based on login attempt
async function checkLoginAttempts() {

    // Step 1: Fetch the login status
    const response = await fetch('/login-status', { cache: 'no-store' });
    const statusData = await response.json();

    // Step 2: Remove any existing error message from previous login attempts
    const existingError = document.getElementById('login_error');
    if (existingError !== null) {
        existingError.parentNode.removeChild(existingError);
    }

    // Step 3: Initialize message variable and set it based on the status
    let message = null;
    
    // Check: First load
    if (statusData.status === 'first_load') {
        return;
    }
    // Check: Empty fields
    else if (statusData.status === 'empty') {
        message = 'Please fill out the login fields.';
    } 
    // Check: Missing reCAPTCHA response
    else if (statusData.status === 'captcha_required') {
        message = 'Please complete the reCAPTCHA check.';
    }
    // Check: Invalid reCAPTCHA response
    else if (statusData.status === 'captcha_failed') {
        message = 'reCAPTCHA verification failed. Please try again.';
    }
    // Check: Invalid username or password (prevents account enumeration)
    else if (statusData.status === 'invalid') {
        message = 'Invalid username or password.';
    } 
    // Check: Successful login
    else if (statusData.status === 'success') {
        return;
    }
    // Check: Server error
    else if (statusData.status === 'server_error') {
        message = 'Login service unavailable. Please try again later.';
    }

    // Step 4: Create and display the error message
    if (message !== null) {
        let error_msg = document.createElement('p');
        error_msg.id = 'login_error';
        error_msg.textContent = message;    // Set the error message text
        error_msg.classList.add('error');

        // Insert the error message before the login button
        document.querySelector('#login_btn').parentNode.insertBefore(error_msg, document.querySelector('#login_btn'));
    }
}

setupRecaptcha();
checkLoginAttempts();