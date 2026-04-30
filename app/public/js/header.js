function renderHeader(activePage) {
    const navItems = [
        { name: 'Home', href: '../html/index.html', id: 'index' },
        { name: 'Posts', href: '../html/posts.html', id: 'posts' },
        { name: 'My Posts', href: '../html/my_posts.html', id: 'my_posts' },
        { name: 'Login', href: '../html/login.html', id: 'login' }
    ];
    const headerMount = document.getElementById('header');

    if (!headerMount) {
        return;
    }

    const header = document.createElement('header');
    const headerLeft = document.createElement('div');
    headerLeft.className = 'site-header-left';

    const logoLink = document.createElement('a');
    logoLink.href = '../html/index.html';
    const logo = document.createElement('img');
    logo.src = '../imgs/logo.png';
    logo.alt = 'Logo';
    logo.className = 'logo';
    logoLink.appendChild(logo);

    const titleLink = document.createElement('a');
    titleLink.href = '../html/index.html';
    const title = document.createElement('span');
    title.className = 'site-title';
    title.textContent = 'Traveller 21';
    titleLink.appendChild(title);

    headerLeft.appendChild(logoLink);
    headerLeft.appendChild(titleLink);
    header.appendChild(headerLeft);

    const nav = document.createElement('nav');
    nav.className = 'site-nav';
    const navList = document.createElement('ul');
    navList.className = 'site-nav-list';

    navItems.forEach(item => {
        const listItem = document.createElement('li');
        const link = document.createElement('a');
        link.href = item.href;
        link.className = 'site-nav-link';

        if (activePage === item.id) {
            link.classList.add('active');
        }

        link.textContent = item.name;
        listItem.appendChild(link);
        navList.appendChild(listItem);
    });

    nav.appendChild(navList);
    header.appendChild(nav);
    headerMount.replaceChildren(header);
}

document.addEventListener('DOMContentLoaded', function() {
    renderHeader(document.body.dataset.page || '');
});
