// header.js
// Usage: renderHeader('index')

function renderHeader(activePage) {
    const navItems = [
        { name: 'Home', href: '../html/index.html', id: 'index' },
        { name: 'Posts', href: '../html/posts.html', id: 'posts' },
        { name: 'My Posts', href: '../html/my_posts.html', id: 'my_posts' },
        { name: 'Login', href: '../html/login.html', id: 'login' }
    ];
    let navHtml = '<nav class="site-nav"><ul class="site-nav-list">';
    navItems.forEach(item => {
        navHtml += `<li><a href="${item.href}" class="site-nav-link${activePage === item.id ? ' active' : ''}">${item.name}</a></li>`;
    });
    navHtml += '</ul></nav>';
        const headerHtml = `
            <header>
                <div class="site-header-left">
                    <a href="../html/index.html"><img src="../imgs/logo.png" alt="Logo" class="logo"></a>
                    <a href="../html/index.html"><span class="site-title">Traveller 21</span></a>
                </div>
                ${navHtml}
            </header>
        `;
    document.getElementById('header').innerHTML = headerHtml;
}
