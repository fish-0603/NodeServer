require('dotenv').config(); // 載入 .env 環境變數，需在其他模組讀取設定前執行
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const axios = require('axios'); // 用於呼叫 Python AI 辨識服務
const { OAuth2Client } = require('google-auth-library');

const db = require('./db'); // 資料庫連線模組

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

// ==========================================
// 1. 認證模組
// ==========================================
app.post('/register', async (req, res) => {
  const { full_name, username, email, password, role, phone } = req.body;
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
    res.json({ success: true, user: { ...user, token } });
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

    // 首次使用此 Google 帳號登入，資料庫尚缺角色與電話，交由前端導向補齊資料頁面
    res.json({ success: true, needsProfile: true, googleId, email, suggestedName });
  } catch (err) {
    console.error("Google 憑證驗證失敗:", err.message);
    res.status(401).json({ success: false, message: "Google 憑證驗證失敗" });
  }
});

// 首次使用 Google 登入的新使用者，於此補齊角色與聯絡電話後建立帳號
app.post('/auth/complete-google-profile', async (req, res) => {
  const { googleId, email, full_name, phone, role } = req.body;
  if (!googleId || !full_name || !phone || !role) {
    return res.status(400).json({ success: false, message: "資料不完整" });
  }

  try {
    const dup = await db.query('SELECT 1 FROM users WHERE google_id = $1', [googleId]);
    if (dup.rows.length > 0) return res.status(400).json({ success: false, message: "此 Google 帳號已註冊過" });

    const username = `google_${googleId.slice(-12)}`;
    const result = await db.query(
      `INSERT INTO users (full_name, username, password_hash, phone, email, role, google_id, auth_provider)
       VALUES ($1, $2, NULL, $3, $4, $5, $6, 'google')
       RETURNING user_id AS id, full_name, username, role, phone`,
      [full_name, username, phone, email || null, role, googleId]
    );
    const user = result.rows[0];
    const token = await issueToken(user.id);
    res.json({ success: true, user: { ...user, token } });
  } catch (err) {
    console.error("補齊 Google 資料失敗:", err.message);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
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
  try {
    const userRes = await db.query('SELECT password_hash FROM users WHERE user_id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ success: false, message: "找不到該使用者" });

    const { password_hash } = userRes.rows[0];
    if (!password_hash) {
      return res.status(400).json({ success: false, message: "此帳號使用 Google 登入，無法透過密碼驗證更新 Email" });
    }

    const isMatch = await bcrypt.compare(password, password_hash);
    if (!isMatch) return res.status(401).json({ success: false, message: "密碼驗證失敗，請輸入正確的密碼" });

    const result = await db.query(
      'UPDATE users SET email = $1 WHERE user_id = $2 RETURNING user_id, email',
      [String(newEmail).trim(), userId]
    );
    res.json({ success: true, message: "Email 更新成功", user: result.rows[0] });
  } catch (err) {
    console.error("Update Email Error:", err.message);
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
      'SELECT user_id, full_name, username, email, phone, role FROM users WHERE user_id = $1',
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
    await db.query(`INSERT INTO connections (blind_id, caregiver_id, status, requester_id) VALUES ($1, $2, 'accepted', $3)`, [blind_id, caregiver_id, myId]);
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
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

// 從左/中/右三區的可行走分數中，排除掉障礙物所在的區域（若有），挑分數最高的一區當建議行走方向
function pickRecommendedZone(walkableScores, excludeZone) {
    const zones = ['left', 'middle', 'right'].filter((z) => z !== excludeZone);
    return zones.reduce((best, z) => (walkableScores[z] > walkableScores[best] ? z : best), zones[0]);
}

// SegFormer 人行道方向建議：正前方沒有明顯人行道時，Python 端會回報左右哪一側有，
// 沒有 YOLO 物體時用這個提醒使用者往人行道方向移動
const SIDEWALK_ZONE_ZH = { left: '左邊', right: '右邊' };

function buildTerrainMessage(sidewalkDirection) {
    const zh = SIDEWALK_ZONE_ZH[sidewalkDirection];
    if (!zh) return null;
    return `${zh}有人行道，建議往${zh}移動`;
}

app.post('/analyze', requireAuth, async (req, res) => {
    const { image, userId } = req.body;

    if (!image) {
        return res.status(400).json({ success: false, message: "未接收到影像數據" });
    }

    try {
        // 將前端傳來的 base64 圖片轉發給 Python AI 服務進行辨識
        // 注意：Python 端(YOLO+SegFormer)回傳的是 { objects: [...], analysis: [{object, distance, distance_m, ratio, zone}, ...],
        // walkableScores: {left, middle, right}, crosswalkInMiddle, skyDominant }
        const aiResponse = await axios.post(PYTHON_AI_URL, { image, userId }, { timeout: 30000 });
        const { analysis, walkableScores, crosswalkInMiddle, skyDominant, sidewalkDirection } = aiResponse.data;

        if (!analysis || analysis.length === 0) {
            return res.status(200).json({
                success: true,
                label: null,
                zone: null,
                recommendedZone: walkableScores ? pickRecommendedZone(walkableScores, null) : null,
                trafficLight: null,
                crosswalkInMiddle: !!crosswalkInMiddle,
                // 沒有偵測到任何物體，斑馬線上自然也不會有障礙物
                crosswalkObstacle: null,
                skyDominant: !!skyDominant,
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

        // 斑馬線上是否有障礙物、是哪一個：簡化判斷，中間區同時偵測到斑馬線、又有物體落在
        // 中間區就算，多個候選時沿用「離鏡頭最近優先」規則只挑一個
        const middleZoneItems = otherItems.filter((item) => item.zone === 'middle');
        const crosswalkObstacle = crosswalkInMiddle && middleZoneItems.length > 0
            ? pickClosest(middleZoneItems).object
            : null;

        // 有紅綠燈就一定回傳，不分遠近、不用跟其他物體搶播報名額
        res.status(200).json({
            success: true,
            label,
            zone,
            recommendedZone,
            trafficLight: trafficLightItem ? trafficLightItem.object : null,
            crosswalkInMiddle: !!crosswalkInMiddle,
            crosswalkObstacle,
            skyDominant: !!skyDominant,
            // 已經有 YOLO 物體時不再疊加人行道方向建議，避免同一段播報塞太多資訊
            terrainMessage: label ? null : buildTerrainMessage(sidewalkDirection),
        });
    } catch (err) {
        console.error('[AI 辨識錯誤]', err.message);
        res.status(502).json({ success: false, message: "AI 辨識服務無法使用", label: null });
    }
});

// Python AI 服務非同步回傳的辨識結果備份端點，對應 apiserver2.py 的 MEMBER_API_URL
app.post('/api/result', async (req, res) => {
    const { objects, analysis } = req.body;
    console.log(`[AI 結果備份] 收到來自 Python 的辨識結果，物件: ${JSON.stringify(objects)}`);

    try {
        if (analysis && analysis.length > 0) {
            // 只存 Node 篩選出的最近/最優先物體，與 /analyze 播報給使用者的對象一致，避免資料庫存入使用者根本沒聽到的次要物體
            const closest = pickClosest(analysis);
            await db.query(
                'INSERT INTO vision_logs(obstacle_type, distance_cm) VALUES($1, $2)',
                [closest.object, closest.distance_m != null ? Math.round(closest.distance_m * 100) : null]
            );
        }
        res.status(200).json({ success: true });
    } catch (err) {
        console.error('[AI 結果備份寫入失敗]', err.message);
        res.status(500).json({ success: false });
    }
});

// 啟動伺服器並監聽通訊埠
app.listen(PORT, () => {
    console.log(`[Server] 伺服器已啟動於 http://localhost:${PORT}`);
});
