const { google } = require('googleapis');
const bcrypt = require('bcryptjs');
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

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    if (!process.env.GOOGLE_DRIVE_FILE_ID) {
        throw new Error("Missing GOOGLE_DRIVE_FILE_ID in environment variables.");
    }
    
    const { email, password } = JSON.parse(event.body);
    if (!email || !password || password.length < 6) {
      return { statusCode: 400, body: 'Email and a password of at least 6 characters are required.' };
    }

    const drive = getDriveClient();
    const fileId = process.env.GOOGLE_DRIVE_FILE_ID;

    const fileRes = await drive.files.get({ fileId, alt: 'media' });
    
    // *** ПОКРАЩЕННЯ: Обробка порожнього або пошкодженого файлу ***
    let currentUsers = [];
    try {
        if (fileRes.data && typeof fileRes.data === 'object') {
            currentUsers = fileRes.data; // Якщо API вже повернуло об'єкт
        } else if (fileRes.data) {
             currentUsers = JSON.parse(fileRes.data); // Якщо API повернуло рядок
        }
    } catch (e) {
        console.warn("Could not parse users.json. Starting with an empty array. Error:", e.message);
        currentUsers = [];
    }
    // *** Кінець покращення ***

    if (Array.isArray(currentUsers) && currentUsers.some(user => user.email === email)) {
      return { statusCode: 409, body: 'User with this email already exists.' };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { email, password: hashedPassword };

    // Переконуємось, що працюємо з масивом
    const usersToSave = Array.isArray(currentUsers) ? [...currentUsers, newUser] : [newUser];

    const buffer = Buffer.from(JSON.stringify(usersToSave, null, 2));
    const bufferStream = new stream.PassThrough();
    bufferStream.end(buffer);

    await drive.files.update({
      fileId,
      media: {
        mimeType: 'application/json',
        body: bufferStream,
      },
    });

    return { statusCode: 201, body: 'User created successfully.' };
  } catch (error) {
    console.error('Signup Error:', error.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'Could not process signup request. Check server logs.' }) };
  }
};
