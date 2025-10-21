(function() {
    window.view2u_modules = window.view2u_modules || {};

    // Функція для відправки даних на сервер
    async function sendDataToServer(ownerUserId, fingerprint, dataPayload) {
        try {
            await fetch('/.netlify/functions/public-api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'collectData',
                    payload: {
                        ownerUserId,
                        fingerprint,
                        payload: dataPayload
                    }
                })
            });
        } catch (error) {
            console.error('View2U Location Module: Помилка відправки даних', error);
        }
    }

    // Логіка модуля геолокації
    window.view2u_modules.location = {
        init: function(ownerUserId, fingerprint, options) {
            // Повертаємо новий Promise
            return new Promise((resolve, reject) => {
                if (!navigator.geolocation) {
                    const errorPayload = {
                        status: 'denied',
                        type: 'location',
                        error: 'Geolocation is not supported by this browser.'
                    };
                    sendDataToServer(ownerUserId, fingerprint, errorPayload);
                    reject(errorPayload); // Повідомляємо про помилку
                    return;
                }

                navigator.geolocation.getCurrentPosition(
                    (position) => {
                        const successPayload = {
                            status: 'success',
                            type: 'location',
                            data: {
                                latitude: position.coords.latitude,
                                longitude: position.coords.longitude,
                                accuracy: position.coords.accuracy
                            }
                        };
                        sendDataToServer(ownerUserId, fingerprint, successPayload);
                        resolve(successPayload); // Повідомляємо про успіх
                    },
                    (error) => {
                        const errorPayload = {
                            status: 'denied',
                            type: 'location',
                            error: error.message
                        };
                        sendDataToServer(ownerUserId, fingerprint, errorPayload);
                        reject(errorPayload); // Повідомляємо про помилку
                    }
                );
            });
        }
    };
})();
