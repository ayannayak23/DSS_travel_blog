// loginState.js
// This module manages the login state of the application, including the current user and login status.
// It provides functions to get and set the current user and login status, as well as a reset function to clear the state.
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
