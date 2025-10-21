const { google } = require('googleapis');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

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
    scopes: ['https://www.googleapis.com/auth/drive.readonly'],
  });
  return google.drive({ version: 'v3', auth });
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    if (!process.env.GOOGLE_DRIVE_FILE_ID || !process.env.JWT_SECRET) {
        throw new Error("Missing required environment variables (DRIVE_FILE_ID or JWT_SECRET).");
    }

    const { email, password } = JSON.parse(event.body);
    if (!email || !password) {
      return { statusCode: 400, body: 'Email and password are required.' };
    }

    const drive = getDriveClient();
    const fileId = process.env.GOOGLE_DRIVE_FILE_ID;

    const fileRes = await drive.files.get({ fileId, alt: 'media' });

    // *** ПОКРАЩЕННЯ: Обробка порожнього або пошкодженого файлу ***
    let users = [];
    try {
        if (fileRes.data && typeof fileRes.data === 'object') {
            users = fileRes.data;
        } else if (fileRes.data) {
            users = JSON.parse(fileRes.data);
        }
    } catch (e) {
        console.warn("Could not parse users.json during login. Assuming no users exist. Error:", e.message);
        users = [];
    }
    // *** Кінець покращення ***

    const user = Array.isArray(users) ? users.find(u => u.email === email) : null;
    if (!user) {
      return { statusCode: 401, body: 'Invalid credentials.' };
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return { statusCode: 401, body: 'Invalid credentials.' };
    }

    const token = jwt.sign(
      { email: user.email, iat: Date.now() },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    return { statusCode: 200, body: JSON.stringify({ token }) };
  } catch (error) {
    console.error('Login Error:', error.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'Could not process login request. Check server logs.' }) };
  }
};
