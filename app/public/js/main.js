// Function to add username in top right corner of every page after user has logged in
async function displayUsername() {
    const response = await fetch('/current-user', { cache: 'no-store' });
    const user_data = await response.json();

    document.querySelector("#login_link").textContent = user_data.username || 'Log in';
}

displayUsername();

// Session Activity Tracking - update activity only when the user interacts with the page
const activityPingIntervalMs = 20 * 1000;
let lastActivityPingTime = 0;

async function pingServer() {
    const now = Date.now();
    if (now - lastActivityPingTime < activityPingIntervalMs) {
        return;
    }
    lastActivityPingTime = now;

    try {
        const response = await fetch('/ping', {
            cache: 'no-store',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (response.status === 401) {
            // Session expired or invalid
            console.warn('Session expired, redirecting to login...');
            window.location.href = '/';
        }
    } catch (error) {
        // Network error, no redirect - user might be temporarily offline
        console.error('Ping error:', error);
    }
}

// Count user interaction as activity
document.addEventListener('click', pingServer);
document.addEventListener('keydown', pingServer);
document.addEventListener('scroll', pingServer, { passive: true });
document.addEventListener('touchstart', pingServer, { passive: true });