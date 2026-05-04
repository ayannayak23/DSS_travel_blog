const PAGE_PATHS = {
    home: '/html/index.html',
    posts: '/html/posts.html',
    myPosts: '/html/my_posts.html',
    login: '/html/login.html'
};

const NAV_ITEMS = [
    { name: 'Home', href: PAGE_PATHS.home, id: 'index' },
    { name: 'Posts', href: PAGE_PATHS.posts, id: 'posts' },
    { name: 'My Posts', href: PAGE_PATHS.myPosts, id: 'my_posts' }
];

function createNavLink(item, activePage) {
    const listItem = document.createElement('li');
    const link = document.createElement('a');

    link.href = item.href;
    link.className = 'site-nav-link';
    link.textContent = item.name;

    if (activePage === item.id) {
        link.classList.add('active');
    }

    listItem.appendChild(link);
    return listItem;
}

function createLoginLink(activePage) {
    const loginLink = document.createElement('a');
    loginLink.href = PAGE_PATHS.login;
    loginLink.className = 'site-user-link';
    loginLink.textContent = 'Log in';

    if (activePage === 'login') {
        loginLink.classList.add('active');
    }

    return loginLink;
}

function createUserMenu(displayName) {
    const menu = document.createElement('div');
    menu.className = 'site-user-menu';

    const toggleButton = document.createElement('button');
    toggleButton.type = 'button';
    toggleButton.className = 'site-user-button';
    toggleButton.innerHTML = '<i class="fa-solid fa-circle-user"></i> &nbsp' + displayName;
    toggleButton.setAttribute('aria-haspopup', 'true');
    toggleButton.setAttribute('aria-expanded', 'false');

    const dropdown = document.createElement('div');
    dropdown.className = 'site-user-dropdown';

    const logoutLink = document.createElement('a');
    logoutLink.href = '/app-logout';
    logoutLink.className = 'site-user-dropdown-link';
    logoutLink.textContent = 'Log out';
    dropdown.appendChild(logoutLink);

    function closeMenu() {
        menu.classList.remove('is-open');
        toggleButton.setAttribute('aria-expanded', 'false');
    }

    toggleButton.addEventListener('click', () => {
        const isOpen = menu.classList.toggle('is-open');
        toggleButton.setAttribute('aria-expanded', String(isOpen));
    });

    document.addEventListener('click', (event) => {
        if (!menu.contains(event.target)) {
            closeMenu();
        }
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeMenu();
        }
    });

    menu.appendChild(toggleButton);
    menu.appendChild(dropdown);
    return menu;
}

async function loadUserControl(userSlot, activePage) {
    try {
        const response = await fetch('/current-user', { cache: 'no-store' });
        const userData = await response.json();
        const displayName = userData.displayName || userData.username;

        if (userData.isAuthenticated && displayName) {
            userSlot.replaceChildren(createUserMenu(displayName));
            return;
        }
    } catch (error) {
        console.error('Failed to load user menu:', error.message);
    }

    userSlot.replaceChildren(createLoginLink(activePage));
}

function renderHeader(activePage) {
    const headerMount = document.getElementById('header');

    if (!headerMount) {
        return;
    }

    const header = document.createElement('header');
    const headerLeft = document.createElement('div');
    headerLeft.className = 'site-header-left';

    const logoLink = document.createElement('a');
    logoLink.href = PAGE_PATHS.home;
    const logo = document.createElement('img');
    logo.src = '../imgs/logo.png';
    logo.alt = 'Traveller 21 logo';
    logo.className = 'logo';
    logoLink.appendChild(logo);

    const titleLink = document.createElement('a');
    titleLink.href = PAGE_PATHS.home;
    const title = document.createElement('span');
    title.className = 'site-title';
    title.textContent = 'Traveller 21';
    titleLink.appendChild(title);

    headerLeft.appendChild(logoLink);
    headerLeft.appendChild(titleLink);

    const nav = document.createElement('nav');
    nav.className = 'site-nav';

    const navList = document.createElement('ul');
    navList.className = 'site-nav-list';
    NAV_ITEMS.forEach((item) => {
        navList.appendChild(createNavLink(item, activePage));
    });

    const userSlot = document.createElement('div');
    userSlot.className = 'site-user-actions';
    userSlot.appendChild(createLoginLink(activePage));

    nav.appendChild(navList);
    nav.appendChild(userSlot);
    header.appendChild(headerLeft);
    header.appendChild(nav);

    headerMount.replaceChildren(header);
    loadUserControl(userSlot, activePage);
}

document.addEventListener('DOMContentLoaded', () => {
    renderHeader(document.body.dataset.page || '');
});
