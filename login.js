// FFGlory Panel Login & Registration Controller
'use strict';

var turnstileToken = '';

window.onTurnstileSuccess = function(token) {
    turnstileToken = token;
    var btn = document.getElementById('signup-btn');
    if (btn) btn.disabled = false;
};

window.onTurnstileExpired = function() {
    turnstileToken = '';
};

// Enable signup button automatically so users on non-production/tunnel are never blocked
setTimeout(function() {
    var btn = document.getElementById('signup-btn');
    if (btn) btn.disabled = false;
}, 1200);

function switchAuthTab(tab) {
    var loginTab = document.getElementById('login-tab');
    var signupTab = document.getElementById('signup-tab');
    var loginForm = document.getElementById('login-form');
    var signupForm = document.getElementById('signup-form');
    var authTitle = document.getElementById('auth-title');
    var authSubtitle = document.getElementById('auth-subtitle');
    var loginError = document.getElementById('login-error');
    var signupSuccess = document.getElementById('signup-success');

    if (loginError) loginError.classList.add('hidden');
    if (signupSuccess) signupSuccess.classList.add('hidden');

    var activeClass = "flex-1 py-3 px-4 rounded-lg text-sm font-medium transition-all bg-gradient-to-r from-[#F5E6D3] to-[#D4C4A8] text-[#0E0E0E] shadow-sm";
    var inactiveClass = "flex-1 py-3 px-4 rounded-lg text-sm font-medium transition-all text-[var(--ng-text-muted)] hover:text-white hover:bg-white/5";

    if (tab === 'login') {
        if (loginForm) loginForm.classList.remove('hidden');
        if (signupForm) signupForm.classList.add('hidden');
        if (loginTab) loginTab.className = activeClass;
        if (signupTab) signupTab.className = inactiveClass;
        if (authTitle) authTitle.textContent = "Welcome Back";
        if (authSubtitle) authSubtitle.innerHTML = 'Sign in to <span class="text-[#F5E6D3] font-semibold">FFGlory</span> panel';
    } else {
        if (loginForm) loginForm.classList.add('hidden');
        if (signupForm) signupForm.classList.remove('hidden');
        if (signupTab) signupTab.className = activeClass;
        if (loginTab) loginTab.className = inactiveClass;
        if (authTitle) authTitle.textContent = "Create Account";
        if (authSubtitle) authSubtitle.innerHTML = 'Join <span class="text-[#F5E6D3] font-semibold">FFGlory</span> panel';
        var sBtn = document.getElementById('signup-btn');
        if (sBtn) sBtn.disabled = false;
    }
}

document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already authenticated
    fetch('/api/auth/me')
        .then(function(r) { return r.json(); })
        .then(function(res) {
            if (res.authenticated) {
                window.location.href = '/';
            }
        })
        .catch(function() {});

    var loginForm = document.getElementById('login-form');
    var signupForm = document.getElementById('signup-form');
    var loginError = document.getElementById('login-error');
    var signupSuccess = document.getElementById('signup-success');

    function showError(msg) {
        if (loginError) {
            loginError.textContent = msg;
            loginError.classList.remove('hidden');
        }
        if (signupSuccess) signupSuccess.classList.add('hidden');
    }

    function showSuccess(msg) {
        if (signupSuccess) {
            signupSuccess.textContent = msg;
            signupSuccess.classList.remove('hidden');
        }
        if (loginError) loginError.classList.add('hidden');
    }

    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            if (loginError) loginError.classList.add('hidden');

            var usernameInput = loginForm.querySelector('input[name="username"]');
            var passwordInput = loginForm.querySelector('input[name="password"]');
            var loginBtn = document.getElementById('login-btn');
            var loginText = document.getElementById('login-text');

            var username = usernameInput ? usernameInput.value.trim() : '';
            var password = passwordInput ? passwordInput.value : '';

            if (!username || !password) {
                showError('Please enter both username and password');
                return;
            }

            if (loginBtn) loginBtn.disabled = true;
            if (loginText) loginText.textContent = 'Signing in...';

            fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username, password: password })
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success || data.ok) {
                    if (loginText) loginText.textContent = 'Success! Loading...';
                    window.location.href = '/';
                } else {
                    showError(data.error || 'Invalid credentials');
                    if (loginBtn) loginBtn.disabled = false;
                    if (loginText) loginText.textContent = 'Sign In';
                }
            })
            .catch(function(err) {
                showError('Network error. Please try again.');
                if (loginBtn) loginBtn.disabled = false;
                if (loginText) loginText.textContent = 'Sign In';
            });
        });
    }

    if (signupForm) {
        signupForm.addEventListener('submit', function(e) {
            e.preventDefault();
            if (loginError) loginError.classList.add('hidden');
            if (signupSuccess) signupSuccess.classList.add('hidden');

            var usernameInput = document.getElementById('signup-username') || signupForm.querySelector('input[name="username"]');
            var passwordInput = document.getElementById('signup-password') || signupForm.querySelector('input[name="password"]');
            var confirmInput = document.getElementById('signup-confirm-password') || signupForm.querySelector('input[name="confirm_password"]');
            var signupBtn = document.getElementById('signup-btn');
            var signupText = document.getElementById('signup-text');

            var username = usernameInput ? usernameInput.value.trim().toLowerCase() : '';
            var password = passwordInput ? passwordInput.value : '';
            var confirmPassword = confirmInput ? confirmInput.value : '';

            if (!username || !password) {
                showError('Please fill in all fields');
                return;
            }
            if (username.length < 3) {
                showError('Username must be at least 3 characters');
                return;
            }
            if (password !== confirmPassword) {
                showError('Passwords do not match');
                return;
            }
            if (password.length < 6) {
                showError('Password must be at least 6 characters');
                return;
            }

            if (signupBtn) signupBtn.disabled = true;
            if (signupText) signupText.textContent = 'Creating Account...';

            fetch('/api/auth/signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username, password: password })
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success || data.ok) {
                    showSuccess('Account created successfully! Redirecting...');
                    setTimeout(function() {
                        window.location.href = '/';
                    }, 1000);
                } else {
                    showError(data.error || 'Failed to create account');
                    if (signupBtn) signupBtn.disabled = false;
                    if (signupText) signupText.textContent = 'Create Account';
                }
            })
            .catch(function(err) {
                showError('Network error. Please try again.');
                if (signupBtn) signupBtn.disabled = false;
                if (signupText) signupText.textContent = 'Create Account';
            });
        });
    }
});
