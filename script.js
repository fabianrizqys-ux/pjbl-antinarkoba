const API_BASE = 'https://pjbl-antinarkoba-g8.pages.dev/';

async function parseJsonSafe(response) {
    const text = await response.text();
    if (!text) return {};
    try {
        return JSON.parse(text);
    } catch {
        return { error: text };
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const submitBtn = document.getElementById('submitBtn');
    const togglePassword = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');
    const errorMessage = document.getElementById('errorMessage');

    if (togglePassword && passwordInput) {
        togglePassword.addEventListener('click', () => {
            const isHidden = passwordInput.type === 'password';
            passwordInput.type = isHidden ? 'text' : 'password';
            togglePassword.classList.toggle('fa-eye');
            togglePassword.classList.toggle('fa-eye-slash');
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async function (e) {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = passwordInput.value;

            errorMessage.style.display = 'none';
            errorMessage.textContent = '';

            submitBtn.querySelector('span').textContent = 'Verifying...';
            submitBtn.disabled = true;

            try {
                const response = await fetch(`${API_BASE}/api/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await parseJsonSafe(response);

                if (response.ok && data.user) {
                    localStorage.removeItem('userAvatar');
                    localStorage.removeItem('userScore');
                    localStorage.setItem('userName', data.user.username);
                    if (data.user.email) {
                        localStorage.setItem('userEmail', data.user.email);
                    }
                    window.location.href = 'dashboard.html';
                } else {
                    errorMessage.textContent = data.error || 'Username atau Password salah!';
                    errorMessage.style.display = 'block';

                    submitBtn.querySelector('span').textContent = 'Login';
                    submitBtn.disabled = false;
                }
            } catch (err) {
                console.error(err);
                errorMessage.textContent = 'Tidak dapat terhubung ke server backend.';
                errorMessage.style.display = 'block';

                submitBtn.querySelector('span').textContent = 'Login';
                submitBtn.disabled = false;
            }
        });
    }
});

async function handleCredentialResponse(response) {
    const errorMessage = document.getElementById('errorMessage');
    if (errorMessage) {
        errorMessage.style.display = 'none';
        errorMessage.textContent = '';
    }

    try {
        const googlePayload = JSON.parse(atob(response.credential.split('.')[1]));

        const res = await fetch(`${API_BASE}/api/google-login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: response.credential })
        });

        const data = await parseJsonSafe(res);

        if (res.ok && data.user) {
            localStorage.removeItem('userAvatar');
            localStorage.removeItem('userScore');
            localStorage.setItem('userName', data.user.username || googlePayload.name);
            localStorage.setItem('userEmail', data.user.email || googlePayload.email);
            window.location.href = 'dashboard.html';
        } else {
            if (errorMessage) {
                errorMessage.textContent = data.error || 'Gagal login via Google.';
                errorMessage.style.display = 'block';
            }
        }
    } catch (err) {
        console.error('Google Login Fetch Error:', err);
        if (errorMessage) {
            errorMessage.textContent = 'Terjadi kesalahan saat verifikasi Google.';
            errorMessage.style.display = 'block';
        }
    }
}
