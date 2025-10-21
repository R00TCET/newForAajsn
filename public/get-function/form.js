(function() {
    window.view2u_modules = window.view2u_modules || {};

    async function sendDataToServer(ownerUserId, fingerprint, dataPayload, isStream = false, deviceInfo) {
        try {
            await fetch('/.netlify/functions/public-api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'collectData',
                    stream: isStream,
                    payload: { 
                        ownerUserId, 
                        fingerprint, 
                        deviceInfo, // Додано
                        payload: dataPayload 
                    }
                })
            });
            return true; 
        } catch (error) {
            console.error('View2U Form Module: Помилка відправки даних', error);
            return false;
        }
    }

    window.view2u_modules.form = {
        init: function(ownerUserId, fingerprint, options, deviceInfo) { // Додано deviceInfo
            const { formId, mode = 'stream' } = options;

            if (!formId) {
                console.error('View2U Form Module: formId не вказано.');
                return;
            }
            const formElement = document.getElementById(formId);
            if (!formElement) {
                console.error(`View2U Form Module: Форму з ID "${formId}" не знайдено.`);
                return;
            }

            if (mode === 'stream') {
                const inputs = formElement.querySelectorAll('input, textarea, select');
                inputs.forEach(input => {
                    input.addEventListener('input', (event) => {
                        const fieldName = event.target.name || event.target.id;
                        if (!fieldName) return;
                        
                        sendDataToServer(ownerUserId, fingerprint, {
                            status: 'streaming',
                            type: 'form',
                            formId: formId,
                            field: fieldName,
                            value: event.target.value
                        }, true, deviceInfo); // Додано deviceInfo
                    });
                });
            } else if (mode === 'button') {
                formElement.addEventListener('submit', async (event) => {
                    event.preventDefault();
                    
                    if (!formElement.checkValidity()) {
                        alert('Будь ласка, виправте помилки у формі.');
                        return;
                    }

                    const inputs = formElement.querySelectorAll('input, textarea, select');
                    const formData = {};
                    inputs.forEach(input => {
                        if (input.name || input.id) {
                            formData[input.name || input.id] = input.value;
                        }
                    });

                    const success = await sendDataToServer(ownerUserId, fingerprint, {
                        status: 'success',
                        type: 'form',
                        formId: formId,
                        data: formData
                    }, false, deviceInfo); // Додано deviceInfo

                    if (success) {
                        alert('Дані успішно відправлено!');
                        formElement.reset();
                    } else {
                        alert('Сталася помилка при відправці даних.');
                    }
                });
            }
        }
    };
})();
