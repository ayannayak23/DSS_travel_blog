// Simple lightbox for viewing post images at a larger size
let imageModal = null;
let imageModalImg = null;

function initImageModal() {
    if (imageModal) {
        return;
    }

    imageModal = document.createElement('div');
    imageModal.classList.add('image-modal');
    imageModal.setAttribute('aria-hidden', 'true');

    imageModalImg = document.createElement('img');
    imageModalImg.classList.add('image-modal-img');
    imageModal.appendChild(imageModalImg);

    const closeButton = document.createElement('button');
    closeButton.classList.add('image-modal-close');
    closeButton.type = 'button';
    closeButton.textContent = 'Close';
    imageModal.appendChild(closeButton);

    closeButton.addEventListener('click', closeImageModal);
    imageModal.addEventListener('click', (event) => {
        if (event.target === imageModal) {
            closeImageModal();
        }
    });

    document.body.appendChild(imageModal);

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeImageModal();
        }
    });
}

function openImageModal(src, alt) {
    if (!imageModal || !imageModalImg) {
        initImageModal();
    }

    imageModalImg.src = src;
    imageModalImg.alt = alt || 'Post image';
    imageModal.classList.add('is-active');
    imageModal.setAttribute('aria-hidden', 'false');
}

function closeImageModal() {
    if (!imageModal || !imageModalImg) {
        return;
    }

    imageModal.classList.remove('is-active');
    imageModal.setAttribute('aria-hidden', 'true');
    imageModalImg.src = '';
}

// Open the lightbox when a post image is clicked
document.addEventListener('click', (event) => {
    const target = event.target;
    if (target && target.classList && target.classList.contains('post-image')) {
        openImageModal(target.src, target.alt);
    }
});

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
