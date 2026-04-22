// Function to add username in top right corner of every page after user has logged in
async function displayUsername() {
    const response = await fetch('/current-user', { cache: 'no-store' });
    const user_data = await response.json();

    document.querySelector("#login_link").textContent = user_data.username || 'Log in';
}

displayUsername();

// Session Activity Tracking - Keep session alive on any user interaction
async function pingServer() {
    try {
        const response = await fetch('/ping', { cache: 'no-store' });
        if (response.status === 401 || response.status === 302) {
            // Session expired or invalid
            console.warn('Session expired, redirecting to login...');
            window.location.href = '/';
        }
    } catch (error) {
        // Network error, don't redirect - user might be temporarily offline
        console.error('Ping error:', error);
    }
}

// Ping server every 2 minutes to keep session alive
setInterval(pingServer, 2 * 60 * 1000);

// Also ping on user interactions
document.addEventListener('click', pingServer);
document.addEventListener('keydown', pingServer);