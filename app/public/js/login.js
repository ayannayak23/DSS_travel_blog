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

checkLoginAttempts();