// Update error message based on login attempt
async function checkLoginAttempts() {
    const response = await fetch('/login-status', { cache: 'no-store' });
    const statusData = await response.json();

    const existingError = document.getElementById('login_error');
    if (existingError !== null) {
        existingError.parentNode.removeChild(existingError);
    }

    let message = null;
    if (statusData.status === 'empty') {
        message = 'Please fill out the login fields.';
    } else if (statusData.status === 'bad_username') {
        message = 'Incorrect username.';
    } else if (statusData.status === 'bad_password') {
        message = 'Incorrect password.';
    } else if (statusData.status === 'server_error') {
        message = 'Login service unavailable.';
    }

    if (message !== null) {
        let error_msg = document.createElement('p');
        error_msg.id = 'login_error';
        error_msg.textContent = message;
        error_msg.classList.add('error');
        document.querySelector('#login_btn').parentNode.insertBefore(error_msg, document.querySelector('#login_btn'));
    }
}

checkLoginAttempts();
