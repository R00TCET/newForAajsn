const { google } = require('googleapis');
const stream = require('stream');

function getDriveClient() {
    if (!process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || !process.env.GOOGLE_PRIVATE_KEY) throw new Error("Missing Google service account credentials.");
    const credentials = { client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL, private_key: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n') };
    const auth = new google.auth.GoogleAuth({ credentials, scopes: ['https://www.googleapis.com/auth/drive'] });
    return google.drive({ version: 'v3', auth });
}

async function readDb(drive) {
    const fileId = process.env.GOOGLE_DRIVE_FILE_ID;
    if (!fileId) throw new Error("Missing GOOGLE_DRIVE_FILE_ID.");
    const res = await drive.files.get({ fileId, alt: 'media' });
    try {
        if (!res.data) return { users: [] };
        return typeof res.data === 'object' ? res.data : JSON.parse(res.data);
    } catch (e) {
        console.warn("Could not parse DB file. Starting with empty state. Error:", e.message);
        return { users: [] };
    }
}

async function writeDb(drive, data) {
    const fileId = process.env.GOOGLE_DRIVE_FILE_ID;
    if (!fileId) throw new Error("Missing GOOGLE_DRIVE_FILE_ID.");
    const buffer = Buffer.from(JSON.stringify(data, null, 2));
    const bufferStream = new stream.PassThrough();
    bufferStream.end(buffer);
    await drive.files.update({ fileId, media: { mimeType: 'application/json', body: bufferStream }});
}

async function performDbOperation(operation) {
    const MAX_RETRIES = 3;
    let lastError = null;
    for (let i = 0; i < MAX_RETRIES; i++) {
        try {
            const drive = getDriveClient();
            const db = await readDb(drive);
            const { updatedDb, result } = await operation(db);
            await writeDb(drive, updatedDb);
            return result;
        } catch (error) {
            lastError = error;
            console.error(`DB Operation failed on attempt ${i + 1}:`, error.message);
            if (i < MAX_RETRIES - 1) {
                await new Promise(res => setTimeout(res, 200 * (i + 1)));
            }
        }
    }
    throw new Error(`Failed to complete DB operation after ${MAX_RETRIES} attempts. Last error: ${lastError.message}`);
}

exports.handler = async function(event) {
    if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };

    const authHeader = event.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
    if (!token || token !== process.env.BOT_API_SECRET) {
        return { statusCode: 401, body: 'Unauthorized' };
    }

    try {
        const { action, payload } = JSON.parse(event.body);

        switch (action) {
            case 'activateUser': {
                const { activationId, chatId, username } = payload;
                const result = await performDbOperation(async (db) => {
                    let userFound = false;
                    for (const user of db.users) {
                        if (user.telegramBinding && user.telegramBinding.activationId === activationId && user.telegramBinding.status === 'pending') {
                            user.telegramBinding.status = 'active';
                            user.telegramBinding.chatId = chatId;
                            user.telegramBinding.username = username;
                            userFound = true;
                            break;
                        }
                    }
                    if (!userFound) {
                        throw new Error('Activation ID not found or already used');
                    }
                    return { updatedDb: db, result: { success: true, message: 'User activated' } };
                });
                return { statusCode: 200, body: JSON.stringify(result) };
            }
            default:
                return { statusCode: 400, body: 'Invalid action.' };
        }
    } catch (error) {
        console.error(`Bot API Error:`, error);
        if (error.message.includes('Activation ID not found')) {
            return { statusCode: 404, body: JSON.stringify({ success: false, message: 'Activation ID not found or already used' }) };
        }
        return { statusCode: 500, body: `Server error. Check function logs. ${error.message}` };
    }
};
