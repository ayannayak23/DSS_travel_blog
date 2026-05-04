function createLoginState() {
    let currentUser = null;
    let loginStatus = 'first_load';

    return {
        getCurrentUser() {
            return currentUser;
        },
        setCurrentUser(username) {
            currentUser = username || null;
        },
        clearCurrentUser() {
            currentUser = null;
        },
        getLoginStatus() {
            return loginStatus;
        },
        setLoginStatus(status) {
            loginStatus = status;
        },
        reset() {
            currentUser = null;
            loginStatus = 'first_load';
        }
    };
}

module.exports = {
    createLoginState
};
