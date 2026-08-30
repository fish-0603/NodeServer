require('dotenv').config(); // 載入 .env 環境變數，需在其他模組讀取設定前執行
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const axios = require('axios'); // 用於呼叫 Python AI 辨識服務
const { OAuth2Client } = require('google-auth-library');

const db = require('./db'); // 資料庫連線模組
const { sendPushToTokens } = require('./fcm'); // Firebase 推播（SOS 通知照護者用）
const { sendVerificationEmail } = require('./mailer'); // 寄送 email 驗證碼

const app = express();
const PORT = process.env.PORT || 3000; // 優先使用環境變數指定的埠號，未設定則預設 3000

app.use(cors());
// 前端會傳送 base64 圖片資料，預設的 100kb 限制不足以容納，故調高上限
app.use(express.json({ limit: '50mb' }));

// Google OAuth 設定：需至 Google Cloud Console 建立 OAuth Client ID 後填入 .env
// 詳細設定步驟請參考 migrations/001_add_google_auth.sql 旁的說明文件
const GOOGLE_WEB_CLIENT_ID = process.env.GOOGLE_WEB_CLIENT_ID || '';
const GOOGLE_ANDROID_CLIENT_ID = process.env.GOOGLE_ANDROID_CLIENT_ID || '';
const GOOGLE_CLIENT_IDS = [GOOGLE_WEB_CLIENT_ID, GOOGLE_ANDROID_CLIENT_ID].filter(
  (id) => id && !id.startsWith('TODO_'),
);
const googleClient = new OAuth2Client();

// Python AI 辨識服務位址（由 PythonServer/apiserver2.py 提供，需另行啟動）
const PYTHON_AI_URL = process.env.PYTHON_AI_URL || 'http://127.0.0.1:5000/api/vision';

// ==========================================
// 認證輔助：登入後簽發 Bearer Token，之後每個需要身分驗證的請求都要帶著它，
// 避免像之前一樣任何人都能靠自己填的 userId 冒用他人身分呼叫 API。
// ==========================================

// 產生一組亂數 token 並寫入 auth_tokens，回傳給前端存起來
async function issueToken(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await db.query('INSERT INTO auth_tokens (token, user_id) VALUES ($1, $2)', [token, userId]);
  return token;
}

// 產生 6 碼驗證碼寫入 email_verification_codes，並非同步寄出驗證信。
// 寄信失敗只記 log、不拋例外——不該讓寄信服務的問題擋到註冊/改信箱本身的流程
// （做法同 notifyCaregiversOfSos：主流程不 await 寄信這一步）
const EMAIL_VERIFICATION_TTL_MS = 15 * 60 * 1000; // 15 分鐘

// 回傳 expiresAt，讓呼叫端可以把過期時間一起回給前端顯示倒數計時
async function issueEmailVerificationCode(userId, email) {
  await db.query('DELETE FROM email_verification_codes WHERE user_id = $1', [userId]);
  const code = crypto.randomInt(100000, 1000000).toString();
  const expiresAt = new Date(Date.now() + EMAIL_VERIFICATION_TTL_MS);
  await db.query(
    'INSERT INTO email_verification_codes (user_id, email, code, expires_at) VALUES ($1, $2, $3, $4)',
    [userId, email, code, expiresAt]
  );
  sendVerificationEmail(email, code).catch((err) =>
    console.error('[Email 驗證] 寄送驗證信失敗:', err.message)
  );
  return expiresAt;
}

// 中介層：驗證 Authorization: Bearer <token>，通過後把使用者 id 掛在 req.authUserId 上
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ success: false, message: '未登入' });
  }
  try {
    const result = await db.query('SELECT user_id FROM auth_tokens WHERE token = $1', [token]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: '登入已過期，請重新登入' });
    }
    req.authUserId = result.rows[0].user_id;
    next();
  } catch (err) {
    console.error('Auth Middleware Error:', err.message);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
}

// 中介層：確認 req.body[field] 或 req.params[field] 等於目前登入的使用者 id，
// 避免登入者拿別人的 userId 存取/修改別人的資料
function requireSelf(field, source = 'body') {
  return (req, res, next) => {
    const value = source === 'params' ? req.params[field] : req.body[field];
    if (String(value) !== String(req.authUserId)) {
      return res.status(403).json({ success: false, message: '無權限存取此使用者的資料' });
    }
    next();
  };
}

// ==========================================
// 0. 健康檢查路由
// ==========================================
app.get('/', (_req, res) => {
    res.status(200).json({
        status: "success",
        message: "SmartGuide Backend Server is running."
    });
});

// 前端已經檢查過一次，這裡是防止有人繞過 App 直接打 API 送出格式不對的 email
const EMAIL_FORMAT_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ==========================================
// 1. 認證模組
// ==========================================
app.post('/register', async (req, res) => {
  const { full_name, username, email, password, role, phone } = req.body;
  if (email && !EMAIL_FORMAT_REGEX.test(email)) {
    return res.status(400).json({ success: false, message: "電子郵件格式錯誤" });
  }
  try {
    const userCheck = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userCheck.rows.length > 0) return res.status(400).json({ success: false, message: "帳號已被註冊" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      `INSERT INTO users (full_name, username, password_hash, phone, email, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING user_id, full_name, username, role`,
      [full_name, username, hashedPassword, phone, email || null, role]
    );
    const user = result.rows[0];
    const token = await issueToken(user.user_id);
    // email 是選填欄位，有填才需要驗證；沒填就跳過，不擋註冊流程本身。
    // issueEmailVerificationCode 內部寄信本身是 fire-and-forget，這裡 await 只是等寫入
    // 驗證碼這兩個很快的 DB 查詢完成，才能把 expiresAt 一起回給前端顯示倒數計時
    let emailVerificationExpiresAt = null;
    if (email) {
      try {
        emailVerificationExpiresAt = await issueEmailVerificationCode(user.user_id, email);
      } catch (err) {
        console.error('[Email 驗證] 註冊時發送驗證碼失敗:', err.message);
      }
    }
    res.json({ success: true, user: { ...user, token }, emailVerificationExpiresAt });
  } catch (err) { console.error("Register Error:", err.message); res.status(500).json({ success: false, message: "伺服器錯誤" }); }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: "帳號不存在" });
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ success: false, message: "密碼錯誤" });
    const token = await issueToken(user.user_id);
    res.json({ success: true, user: { id: user.user_id, username: user.username, role: user.role, full_name: user.full_name, phone: user.phone, token } });
  } catch (err) { console.error("Login Error:", err.message); res.status(500).json({ success: false, message: "伺服器錯誤" }); }
});

// Google 登入：前端使用 @react-native-google-signin/google-signin 取得 idToken 後呼叫此路由
app.post('/auth/google', async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ success: false, message: "缺少 Google 憑證" });
  if (GOOGLE_CLIENT_IDS.length === 0) {
    return res.status(500).json({ success: false, message: "後端尚未設定 Google Client ID" });
  }

  try {
    const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_IDS });
    const payload = ticket.getPayload();
    const googleId = payload.sub;
    const email = payload.email || null;
    const suggestedName = payload.name || "";

    const existing = await db.query('SELECT * FROM users WHERE google_id = $1', [googleId]);
    if (existing.rows.length > 0) {
      const user = existing.rows[0];
      const token = await issueToken(user.user_id);
      return res.json({
        success: true,
        user: { id: user.user_id, username: user.username, role: user.role, full_name: user.full_name, phone: user.phone, token },
      });
    }

    // 沒有 google_id 對應的帳號時，如果 Google 已驗證這個 email（不是使用者自己填的、
    // 是 Google 端確認過擁有權的），才進一步比對是否有帳密註冊、且「自己也驗證過」同一個
    // email 的帳號——兩邊都驗證過才能安全地自動綁定登入，避免有人搶先拿別人的 email
    // 帳密註冊、等對方 Google 登入時被誤導綁到那個帳號
    if (email && payload.email_verified) {
      const localMatch = await db.query(
        'SELECT * FROM users WHERE email = $1 AND email_verified = true',
        [email]
      );
      if (localMatch.rows.length > 0) {
        const user = localMatch.rows[0];
        await db.query('UPDATE users SET google_id = $1 WHERE user_id = $2', [googleId, user.user_id]);
        const token = await issueToken(user.user_id);
        return res.json({
          success: true,
          user: { id: user.user_id, username: user.username, role: user.role, full_name: user.full_name, phone: user.phone, token },
        });
      }
    }

    // 首次使用此 Google 帳號登入，資料庫尚缺角色與電話，交由前端導向補齊資料頁面。
    // 這裡改帶回 idToken 本身（而不是拆開的 googleId/email 字串），讓補齊資料時能重新驗證，
    // 不能讓 client 自己宣稱任意 googleId/email 就建立帳號
    res.json({ success: true, needsProfile: true, idToken, suggestedName });
  } catch (err) {
    console.error("Google 憑證驗證失敗:", err.message);
    res.status(401).json({ success: false, message: "Google 憑證驗證失敗" });
  }
});

// 首次使用 Google 登入的新使用者，於此補齊角色與聯絡電話後建立帳號。
// 不信任 client 傳來的 googleId/email 字串（那樣的話任何人都能捏造 email 建立一個
// 看起來像已驗證的帳號），改成重新驗證 idToken 本身，跟 /auth/google 用同一套驗證方式
app.post('/auth/complete-google-profile', async (req, res) => {
  const { idToken, full_name, phone, role } = req.body;
  if (!idToken || !full_name || !phone || !role) {
    return res.status(400).json({ success: false, message: "資料不完整" });
  }

  try {
    const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_IDS });
    const payload = ticket.getPayload();
    const googleId = payload.sub;
    const email = payload.email || null;

    const dup = await db.query('SELECT 1 FROM users WHERE google_id = $1', [googleId]);
    if (dup.rows.length > 0) return res.status(400).json({ success: false, message: "此 Google 帳號已註冊過" });

    // Google 已經驗證過這個 email 的擁有權，不需要再走一次自家驗證碼流程
    const emailVerified = !!(email && payload.email_verified);

    const username = `google_${googleId.slice(-12)}`;
    const result = await db.query(
      `INSERT INTO users (full_name, username, password_hash, phone, email, role, google_id, email_verified)
       VALUES ($1, $2, NULL, $3, $4, $5, $6, $7)
       RETURNING user_id AS id, full_name, username, role, phone`,
      [full_name, username, phone, email, role, googleId, emailVerified]
    );
    const user = result.rows[0];
    const token = await issueToken(user.id);
    res.json({ success: true, user: { ...user, token } });
  } catch (err) {
    // partial unique index（users_verified_email_idx）衝突：這個 email 已經被另一個已驗證帳號使用
    if (err.code === '23505') {
      return res.status(409).json({ success: false, message: "這個信箱已被其他帳號驗證使用" });
    }
    console.error("補齊 Google 資料失敗:", err.message);
    res.status(500).json({ success: false, message: "Google 憑證驗證失敗或伺服器錯誤" });
  }
});

// App 設定頁的「編輯個人資料」功能會呼叫此路由更新顯示名稱
app.put('/update-name', requireAuth, requireSelf('userId'), async (req, res) => {
  const { userId, name } = req.body;
  if (!userId || !name || !String(name).trim()) {
    return res.status(400).json({ success: false, message: "資料不完整" });
  }
  try {
    const result = await db.query(
      'UPDATE users SET full_name = $1 WHERE user_id = $2 RETURNING user_id, full_name',
      [String(name).trim(), userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: "找不到使用者" });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error("Update Name Error:", err.message);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
  }
});

// 更新 Email：需先用密碼驗證身分（Google 登入帳號沒有 password_hash，無法用這個方式驗證）
app.put('/update-email', requireAuth, requireSelf('userId'), async (req, res) => {
  const { userId, newEmail, password } = req.body;
  if (!userId || !newEmail || !password) {
    return res.status(400).json({ success: false, message: "資料不完整" });
  }
  if (!EMAIL_FORMAT_REGEX.test(newEmail)) {
    return res.status(400).json({ success: false, message: "電子郵件格式錯誤" });
  }
  try {
    const userRes = await db.query('SELECT password_hash FROM users WHERE user_id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ success: false, message: "找不到該使用者" });

    const { password_hash } = userRes.rows[0];
    if (!password_hash) {
      return res.status(400).json({ success: false, message: "此帳號使用 Google 登入，無法透過密碼驗證更新 Email" });
    }

    const isMatch = await bcrypt.compare(password, password_hash);
    if (!isMatch) return res.status(401).json({ success: false, message: "密碼驗證失敗，請輸入正確的密碼" });

    // 新 email 還沒驗證過，不能沿用舊 email 的已驗證狀態
    const trimmedEmail = String(newEmail).trim();
    const result = await db.query(
      'UPDATE users SET email = $1, email_verified = false WHERE user_id = $2 RETURNING user_id, email',
      [trimmedEmail, userId]
    );
    // email 本身已經更新成功，就算驗證碼發送失敗也不該讓這支 API 回傳失敗，只記 log
    let emailVerificationExpiresAt = null;
    try {
      emailVerificationExpiresAt = await issueEmailVerificationCode(userId, trimmedEmail);
    } catch (err) {
      console.error('[Email 驗證] 改信箱後發送驗證碼失敗:', err.message);
    }
    res.json({
      success: true,
      message: "Email 更新成功，請至新信箱完成驗證",
      user: result.rows[0],
      emailVerificationExpiresAt,
    });
  } catch (err) {
    console.error("Update Email Error:", err.message);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
  }
});

// 輸入收到的 6 碼驗證碼完成信箱驗證
app.post('/verify-email', requireAuth, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ success: false, message: "請輸入驗證碼" });

  try {
    const result = await db.query(
      'SELECT id, email FROM email_verification_codes WHERE user_id = $1 AND code = $2 AND expires_at > now()',
      [req.authUserId, String(code).trim()]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: "驗證碼錯誤或已過期" });
    }

    await db.query('UPDATE users SET email_verified = true WHERE user_id = $1', [req.authUserId]);
    await db.query('DELETE FROM email_verification_codes WHERE user_id = $1', [req.authUserId]);
    res.json({ success: true, message: "信箱驗證成功" });
  } catch (err) {
    // partial unique index（users_verified_email_idx）衝突：這個信箱已經被另一個已驗證帳號使用
    if (err.code === '23505') {
      return res.status(409).json({ success: false, message: "這個信箱已被其他帳號驗證使用" });
    }
    console.error("Verify Email Error:", err.message);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
  }
});

// 沒收到驗證信或驗證碼過期時，重新寄送一組新的
app.post('/resend-verification-email', requireAuth, async (req, res) => {
  try {
    const userRes = await db.query('SELECT email FROM users WHERE user_id = $1', [req.authUserId]);
    const email = userRes.rows[0]?.email;
    if (!email) return res.status(400).json({ success: false, message: "此帳號尚未設定 email" });

    const emailVerificationExpiresAt = await issueEmailVerificationCode(req.authUserId, email);
    res.json({ success: true, message: "驗證碼已重新寄送", emailVerificationExpiresAt });
  } catch (err) {
    console.error("Resend Verification Error:", err.message);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
  }
});

// 更新密碼：需先驗證舊密碼（Google 登入帳號沒有 password_hash，無法用這個方式驗證）
app.put('/update-password', requireAuth, requireSelf('userId'), async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;
  if (!userId || !oldPassword || !newPassword) {
    return res.status(400).json({ success: false, message: "資料不完整" });
  }
  try {
    const userRes = await db.query('SELECT password_hash FROM users WHERE user_id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ success: false, message: "找不到該使用者" });

    const { password_hash } = userRes.rows[0];
    if (!password_hash) {
      return res.status(400).json({ success: false, message: "此帳號使用 Google 登入，無法透過密碼變更方式修改密碼" });
    }

    const isMatch = await bcrypt.compare(oldPassword, password_hash);
    if (!isMatch) return res.status(401).json({ success: false, message: "原本的密碼輸入錯誤" });

    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [newHashedPassword, userId]);
    res.json({ success: true, message: "密碼修改成功" });
  } catch (err) {
    console.error("Update Password Error:", err.message);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
  }
});

// 設定頁編輯個人資料頁面載入時，用來取得目前的名稱與 Email
app.get('/user-profile/:userId', requireAuth, requireSelf('userId', 'params'), async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await db.query(
      'SELECT user_id, full_name, username, email, email_verified, phone, role FROM users WHERE user_id = $1',
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: "找不到該使用者" });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error("Get User Profile Error:", err.message);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
  }
});

// 登出：把目前使用的 token 從資料庫刪除，讓它立即失效
app.post('/logout', requireAuth, async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  try {
    await db.query('DELETE FROM auth_tokens WHERE token = $1', [token]);
    res.json({ success: true });
  } catch (err) {
    console.error("Logout Error:", err.message);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
  }
});

// ==========================================
// 2. 聯絡人模組
// ==========================================
app.post('/bind-direct', requireAuth, requireSelf('myId'), async (req, res) => {
  const { myId, targetId } = req.body;
  try {
    const checkResult = await db.query(`SELECT * FROM connections WHERE (blind_id = $1 AND caregiver_id = $2) OR (blind_id = $2 AND caregiver_id = $1)`, [myId, targetId]);
    if (checkResult.rows.length > 0) return res.status(400).json({ success: false, message: "已經綁定" });
    const userRes = await db.query("SELECT user_id, role FROM users WHERE user_id IN ($1, $2)", [myId, targetId]);
    const users = userRes.rows;
    let blind_id = users.find(u => u.role === 'blind')?.user_id;
    let caregiver_id = users.find(u => u.role === 'caregiver')?.user_id;
    await db.query(`INSERT INTO connections (blind_id, caregiver_id, status) VALUES ($1, $2, 'accepted')`, [blind_id, caregiver_id]);
    res.json({ success: true, message: "綁定成功" });
  } catch (err) { console.error("Bind Error:", err.message); res.status(500).json({ success: false, message: "資料庫錯誤" }); }
});

app.get('/contacts/:userId', requireAuth, requireSelf('userId', 'params'), async (req, res) => {
  try {
    const result = await db.query(
      `SELECT u.user_id as id, u.full_name as username, u.phone, u.role, c.id as connection_id, COALESCE(c.is_emergency, false) as is_emergency
       FROM connections c
       JOIN users u ON (u.user_id = c.blind_id OR u.user_id = c.caregiver_id)
       WHERE (c.blind_id = $1 OR c.caregiver_id = $1) AND u.user_id != $1 AND c.status = 'accepted'
       ORDER BY c.is_emergency DESC`, [req.params.userId]
    );
    res.json({ success: true, contacts: result.rows });
  } catch (err) { console.error("Contacts Error:", err.message); res.status(500).json({ success: false, error: "無法獲取聯絡人" }); }
});

app.post('/reject-bind', requireAuth, async (req, res) => {
  try {
    // 只能刪除自己有份的連結，避免拿別人的 connectionId 亂刪
    const result = await db.query(
      'DELETE FROM connections WHERE id = $1 AND (blind_id = $2 OR caregiver_id = $2)',
      [req.body.connectionId, req.authUserId]
    );
    if (result.rowCount === 0) {
      return res.status(403).json({ success: false, message: '無權限刪除此聯絡人關係' });
    }
    res.json({ success: true });
  } catch (err) { console.error("Reject Bind Error:", err.message); res.status(500).json({ success: false }); }
});

app.post('/set-emergency', requireAuth, requireSelf('blindId'), async (req, res) => {
  const { blindId, connectionId } = req.body;
  try {
    await db.query('UPDATE connections SET is_emergency = false WHERE blind_id = $1', [blindId]);
    if (connectionId !== -1) {
      // 加上 blind_id 限制，避免登入者拿到別人的 connectionId 就能改到別人的緊急聯絡人設定
      const result = await db.query(
        'UPDATE connections SET is_emergency = true WHERE id = $1 AND blind_id = $2',
        [connectionId, blindId]
      );
      if (result.rowCount === 0) {
        return res.status(403).json({ success: false, message: '無權限操作此聯絡人關係' });
      }
    }
    res.json({ success: true });
  } catch (err) {
    console.error("Emergency Update Error:", err);
    res.status(500).json({ success: false });
  }
});

// ==========================================
// 3. SOS 警報與歷史紀錄模組
// ==========================================

// 查詢視障者目前已綁定（accepted）的照護者 fcm_token 並推播；在 /sos 回應之後才呼叫（不 await），
// 避免推播的網路來回拖慢撥打緊急電話的動作，失敗只記 log 不影響 SOS 本身
async function notifyCaregiversOfSos(blindUserId) {
  const caregiverRes = await db.query(
    `SELECT u.fcm_token
     FROM connections c
     JOIN users u ON u.user_id = c.caregiver_id
     WHERE c.blind_id = $1 AND c.status = 'accepted' AND u.fcm_token IS NOT NULL`,
    [blindUserId]
  );
  const tokens = caregiverRes.rows.map((r) => r.fcm_token).filter(Boolean);
  if (tokens.length === 0) return;

  const nameRes = await db.query('SELECT full_name FROM users WHERE user_id = $1', [blindUserId]);
  const blindName = nameRes.rows[0]?.full_name || '使用者';

  await sendPushToTokens(
    tokens,
    { title: '🚨 緊急求助通知', body: `${blindName} 已觸發緊急求助，請盡速確認狀況` },
    { type: 'SOS', userId: String(blindUserId) },
  );
}

app.post('/sos', requireAuth, requireSelf('userId'), async (req, res) => {
  const { userId, latitude, longitude, eventType } = req.body;
  try {
    // 寫入 SOS 警報紀錄
    await db.query(
      `INSERT INTO sos_events (user_id, latitude, longitude, event_type) VALUES ($1, $2, $3, $4)`,
      [userId, latitude, longitude, eventType]
    );

    // 查詢該使用者已設定的緊急聯絡人電話，供前端後續撥打
    const contactRes = await db.query(`
      SELECT u.phone
      FROM connections c
      JOIN users u ON (u.user_id = c.blind_id OR u.user_id = c.caregiver_id)
      WHERE (c.blind_id = $1 OR c.caregiver_id = $1)
      AND u.user_id != $1
      AND c.is_emergency = true
      LIMIT 1`, [userId]);

    const emergencyPhone = contactRes.rows.length > 0 ? contactRes.rows[0].phone : null;

    res.json({ success: true, emergencyPhone });

    notifyCaregiversOfSos(userId).catch((err) =>
      console.error('[SOS 推播] 通知照護者失敗:', err.message)
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
  }
});

// App 登入成功、或每次啟動取得新的 FCM token 時呼叫，把 token 存進 users 表，
// /sos 觸發時才找得到這個使用者的裝置該送去哪裡
app.post('/push-token', requireAuth, async (req, res) => {
  const { fcmToken } = req.body;
  if (!fcmToken) return res.status(400).json({ success: false, message: '缺少 fcmToken' });
  try {
    await db.query('UPDATE users SET fcm_token = $1 WHERE user_id = $2', [fcmToken, req.authUserId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Push Token Error:', err.message);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

app.get('/sos-history/:userId', requireAuth, requireSelf('userId', 'params'), async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await db.query(
      `SELECT e.id, u.full_name as name, e.event_type as event, e.created_at as time, e.latitude, e.longitude
       FROM sos_events e
       JOIN users u ON e.user_id = u.user_id
       JOIN connections c ON e.user_id = c.blind_id
       WHERE c.caregiver_id = $1
       ORDER BY e.created_at DESC`,
      [userId]
    );
    res.json({ success: true, requests: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "資料庫查詢失敗" });
  }
});

// ==========================================
// 4. 前端即時影像辨識：接收截圖，轉發給 Python 辨識後回傳結果
// ==========================================

// 從 Python 回傳的 analysis 陣列中挑出最該優先警示的一個物體：
// 先比「近/中/遠」等級，同等級時優先比實際公尺數（distance_m 較準），沒有公尺數的類別才退回比面積比例（ratio）。
// 不篩掉「遠」距離的物體——YOLO 常常因為物體偏遠而信心值不夠，乾脆不篩距離，有偵測到就有機會播
function pickClosest(analysis) {
    const getRank = (item) => item.distance.startsWith('近') ? 0 : item.distance.startsWith('中') ? 1 : 2;
    return analysis.reduce((a, b) => {
        const rankA = getRank(a), rankB = getRank(b);
        if (rankA !== rankB) return rankA < rankB ? a : b;
        if (a.distance_m != null && b.distance_m != null) return a.distance_m < b.distance_m ? a : b;
        if (a.distance_m != null) return a;
        if (b.distance_m != null) return b;
        return b.ratio > a.ratio ? b : a;
    });
}

// 紅綠燈是號誌狀態、不是「離使用者多近的障礙物」，不能跟其他物體一起比距離，
// 所以要先從 analysis 裡把它獨立出來，剩下的物體才拿去比最近
const TRAFFIC_LIGHT_LABELS = new Set(['紅燈', '綠燈']);

// SegFormer 行走方向決策：
// - 沒有障礙物時，不使用 walkableScores 強制推薦方向；正常直行不需要額外播報。
//   若正前方缺乏明顯人行道，交由 sidewalkDirection 提醒往左/右的人行道移動。
// - 有障礙物時，先排除障礙物所在區，再比較剩餘區域。
// - 候選區域分數太低，或最佳與次佳差距太小時，不硬給方向，避免模型不確定卻誤導使用者。
const WALKABLE_MIN_SCORE = 0.15;
const DIRECTION_MIN_GAP = 0.08;

function pickRecommendedZone(walkableScores, excludeZone) {
    if (!walkableScores || !excludeZone) return null;

    const zones = ['left', 'middle', 'right']
        .filter((z) => z !== excludeZone);

    if (zones.length === 0) return null;

    const ranked = zones
        .map((zone) => ({
            zone,
            score: Number(walkableScores[zone] ?? 0),
        }))
        .sort((a, b) => b.score - a.score);

    const best = ranked[0];
    const second = ranked[1];

    if (!best || best.score < WALKABLE_MIN_SCORE) {
        return null;
    }

    if (second && (best.score - second.score) < DIRECTION_MIN_GAP) {
        return null;
    }

    return best.zone;
}

// SegFormer 人行道方向建議：正前方沒有明顯人行道時，Python 端會回報左右哪一側有，
// 沒有 YOLO 物體時用這個提醒使用者往人行道方向移動
const SIDEWALK_ZONE_ZH = { left: '左邊', right: '右邊' };

function buildTerrainMessage(sidewalkDirection) {
    const zh = SIDEWALK_ZONE_ZH[sidewalkDirection];
    if (!zh) return null;
    return `${zh}有人行道，建議往${zh}移動`;
}

// 斑馬線「前方確認」需要連續命中才算數：SegFormer 是逐幀獨立推論，沒有時序穩定性，
// 單一幀的雜訊（反光、遮擋、拍攝角度）就可能讓某一幀誤判有/沒有斑馬線。
// App 端每 5 秒呼叫一次 /analyze，這裡用登入者 id 追蹤連續命中次數；只要斷一次就整個歸零，
// 不是容錯的滑動視窗，要重新累積滿才會再次判定「前方確定有斑馬線」
const CROSSWALK_CONFIRM_STREAK = 3; // 約 6 秒（App 端 2 秒拍一次 * 3）持續偵測到才算數
const crosswalkStreaks = new Map(); // userId -> 目前連續命中次數

function updateCrosswalkStreak(userId, crosswalkAhead) {
    const streak = crosswalkAhead ? (crosswalkStreaks.get(userId) || 0) + 1 : 0;
    crosswalkStreaks.set(userId, streak);
    return streak >= CROSSWALK_CONFIRM_STREAK;
}

app.post('/analyze', requireAuth, async (req, res) => {
    // frameId/captureTime 只是原樣轉發給 Python 用來在 log 裡標記「這是哪一張照片」，
    // 方便事後對照除錯，App 端自己算辨識結果會不會過期用的是本地時間，不依賴這裡的回傳值
    const { image, frameId, captureTime } = req.body;
    // 用已驗證的登入者 id（不是 client 帶的 body.userId），斑馬線連續 frame 計數才不會被亂帶的 userId 污染
    const userId = req.authUserId;

    if (!image) {
        return res.status(400).json({ success: false, message: "未接收到影像數據" });
    }

    try {
        // 將前端傳來的 base64 圖片轉發給 Python AI 服務進行辨識
        // 注意：Python 端(YOLO+SegFormer)回傳的是 { objects: [...], analysis: [{object, distance, distance_m, ratio, zone, onCrosswalk}, ...],
        // walkableScores: {left, middle, right}, crosswalkAhead, terrainDetected, isBlackFrame }
        const aiResponse = await axios.post(PYTHON_AI_URL, { image, userId, frameId, captureTime }, { timeout: 30000 });
        const { analysis, walkableScores, crosswalkAhead, terrainDetected, isBlackFrame, sidewalkDirection } = aiResponse.data;

        // 斑馬線流程：SegFormer 判斷前方 ROI 有足夠面積的斑馬線 → 連續數個 frame 都存在才確認
        // →（前面的物體偵測結果裡）找行人號誌 → 有燈號就照燈號提示通行/等待，沒有燈號才看
        // 斑馬線面積上有沒有障礙物。crosswalkConfirmed 就是這條流程「已確認前方有斑馬線」的開關
        const crosswalkConfirmed = updateCrosswalkStreak(userId, !!crosswalkAhead);

        if (!analysis || analysis.length === 0) {
            return res.status(200).json({
                success: true,
                label: null,
                zone: null,
                recommendedZone: walkableScores ? pickRecommendedZone(walkableScores, null) : null,
                trafficLight: null,
                crosswalkInMiddle: crosswalkConfirmed,
                // 沒有偵測到任何物體，斑馬線上自然也不會有障礙物
                crosswalkObstacle: null,
                terrainDetected: !!terrainDetected,
                isBlackFrame: !!isBlackFrame,
                // 沒有 YOLO 物體時才用人行道方向建議佔用第一段播報名額，避免同時念兩件事
                terrainMessage: buildTerrainMessage(sidewalkDirection),
            });
        }

        const trafficLightItem = analysis.find((item) => TRAFFIC_LIGHT_LABELS.has(item.object));
        const otherItems = analysis.filter((item) => !TRAFFIC_LIGHT_LABELS.has(item.object));

        let label = null, zone = null;
        if (otherItems.length > 0) {
            // 同時有多個物體分別在不同區域時，沿用「離鏡頭最近優先」規則，只播一個
            const closest = pickClosest(otherItems);
            // label 直接使用 Python 已翻譯好的中文物體名稱（如「車」「行人」），前端不需再對照字典
            label = closest.object;
            zone = closest.zone;
        }

        // 建議行走方向：排除掉障礙物所在區，從剩下的區域挑可行走分數最高的一區
        const recommendedZone = walkableScores ? pickRecommendedZone(walkableScores, zone) : null;

        // 斑馬線上是否有障礙物：只採信 Python 端算出跟斑馬線像素區域有實際重疊的物體（onCrosswalk），
        // 不再用「同一個中間分區」這種粗略判斷，避免把斑馬線兩側、但其實沒踩在線上的東西也算進去。
        // 且只有確認前方有斑馬線時才需要看這個，避免跟一般障礙物提示搶著播
        const crosswalkObstacleItems = crosswalkConfirmed ? otherItems.filter((item) => item.onCrosswalk) : [];
        const crosswalkObstacle = crosswalkObstacleItems.length > 0
            ? pickClosest(crosswalkObstacleItems).object
            : null;

        const trafficLightName = crosswalkConfirmed && trafficLightItem ? trafficLightItem.object : null;

        // 🔍 後端偵錯日誌：在 res.status(200) 回傳給 App 前，先在控制台印出結果，方便確認
        // Node 有沒有成功收到並解析 Python 那邊回傳的辨識結果
        console.log(`[Analyze] 使用者: ${userId} | 成功解析 -> label: "${label}", trafficLight: "${trafficLightName}"`);

        res.status(200).json({
            success: true,
            label,
            zone,
            recommendedZone,
            // 紅綠燈提示是「已確認前方有斑馬線」流程下的一步，還沒連續確認前不提前播報燈號，
            // 避免跟一般障礙物提示同時搶播報名額
            trafficLight: trafficLightName,
            crosswalkInMiddle: crosswalkConfirmed,
            crosswalkObstacle,
            terrainDetected: !!terrainDetected,
            isBlackFrame: !!isBlackFrame,
            // 已經有 YOLO 物體時不再疊加人行道方向建議，避免同一段播報塞太多資訊
            terrainMessage: label ? null : buildTerrainMessage(sidewalkDirection),
        });
    } catch (err) {
        console.error('[AI 辨識錯誤]', err.message);
        res.status(502).json({ success: false, message: "AI 辨識服務無法使用", label: null });
    }
});

// 啟動伺服器並監聽通訊埠
app.listen(PORT, () => {
    console.log(`[Server] 伺服器已啟動於 http://localhost:${PORT}`);
});
