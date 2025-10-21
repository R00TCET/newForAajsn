(function() {
    // Ініціалізуємо глобальний об'єкт, якщо він ще не існує
    window.view2u = window.view2u || {};
    window.view2u_modules = window.view2u_modules || {};

    let fpPromise = null;
    let fingerprintCache = null;

    // Функція для завантаження FingerprintJS
    function loadFingerprint() {
        if (fpPromise) return fpPromise;
        fpPromise = new Promise((resolve, reject) => {
            if (window.FingerprintJS) {
                return resolve(window.FingerprintJS.load());
            }
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js';
            script.onload = () => resolve(window.FingerprintJS.load());
            script.onerror = reject;
            document.head.appendChild(script);
        });
        return fpPromise;
    }

    // Функція для отримання відбитку (з кешуванням)
    async function getFingerprint() {
        if (fingerprintCache) return fingerprintCache;
        const fp = await loadFingerprint();
        const result = await fp.get();
        fingerprintCache = result.visitorId;
        return fingerprintCache;
    }

    // Функція для збору інформації про пристрій
    function getDeviceInfo() {
        return {
            userAgent: navigator.userAgent,
            language: navigator.language,
            screenResolution: `${window.screen.width}x${window.screen.height}`,
            windowResolution: `${window.innerWidth}x${window.innerHeight}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            platform: navigator.platform,
            cookiesEnabled: navigator.cookieEnabled,
        };
    }
    
    // Функція для відправки початкових даних
    async function sendInitialDataToServer(ownerUserId, fingerprint, deviceInfo) {
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
                            type: 'device_info',
                            status: 'success',
                            data: deviceInfo
                        }
                    }
                })
            });
        } catch (error) {
            console.error('View2U Bridge: Помилка відправки початкових даних', error);
        }
    }

    // *** НОВА ФУНКЦІЯ ***
    // Ініціалізація, яка викликається при завантаженні сторінки для збору даних
    window.view2u.init = async function() {
        try {
            const ownerUserId = new URLSearchParams(window.location.search).get('id');
            if (!ownerUserId) return; // Не робити нічого, якщо немає ID
            
            const fingerprint = await getFingerprint();
            const deviceInfo = getDeviceInfo();
            
            // Відправляємо дані на сервер у фоновому режимі
            await sendInitialDataToServer(ownerUserId, fingerprint, deviceInfo);

        } catch (error) {
            console.error("View2U Bridge Init Error:", error);
        }
    };

    // Головний метод для виклику модулів, тепер асинхронний і повертає результат
    window.view2u.execute = async function(moduleName, options = {}) {
        try {
            // Отримуємо ID власника сторінки з URL
            const ownerUserId = new URLSearchParams(window.location.search).get('id');
            if (!ownerUserId) {
                throw new Error("View2U Bridge: Неможливо визначити ID власника сторінки.");
            }
            
            // Отримуємо відбиток пристрою
            const fingerprint = await getFingerprint();

            // Функція для завантаження та ініціалізації модуля
            const initModule = () => {
                return window.view2u_modules[moduleName].init(ownerUserId, fingerprint, options);
            };

            // Перевіряємо, чи модуль вже завантажено
            if (window.view2u_modules[moduleName]) {
                return initModule();
            } else {
                return new Promise((resolve, reject) => {
                    const script = document.createElement('script');
                    script.src = `/get-function/${moduleName}.js`;
                    script.onload = () => {
                        if (window.view2u_modules[moduleName] && typeof window.view2u_modules[moduleName].init === 'function') {
                            resolve(initModule());
                        } else {
                            reject(new Error(`View2U Bridge: Модуль "${moduleName}" завантажено, але він не має методу init.`));
                        }
                    };
                    script.onerror = () => {
                        reject(new Error(`View2U Bridge: Не вдалося завантажити модуль "${moduleName}".`));
                    };
                    document.head.appendChild(script);
                });
            }
        } catch (error) {
            console.error("View2U Bridge Error:", error);
            return Promise.reject(error);
        }
    };
})();
