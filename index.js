require('dotenv').config(); // 載入 .env 環境變數，需在其他模組讀取設定前執行
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');
const { spawn } = require('child_process');
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

// Python AI 辨識服務位址（由 vision_ai.py 提供，需另行啟動）
const PYTHON_AI_URL = process.env.PYTHON_AI_URL || 'http://127.0.0.1:5000/predict';

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
    res.json({ success: true, user: result.rows[0] });
  } catch (err) { res.status(500).json({ success: false, message: "伺服器錯誤" }); }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: "帳號不存在" });
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ success: false, message: "密碼錯誤" });
    res.json({ success: true, user: { id: user.user_id, username: user.username, role: user.role, full_name: user.full_name, phone: user.phone } });
  } catch (err) { res.status(500).json({ success: false, message: "伺服器錯誤" }); }
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
      return res.json({
        success: true,
        user: { id: user.user_id, username: user.username, role: user.role, full_name: user.full_name, phone: user.phone },
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
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error("補齊 Google 資料失敗:", err.message);
    res.status(500).json({ success: false, message: "伺服器錯誤" });
  }
});

// ==========================================
// 2. 聯絡人模組
// ==========================================
app.post('/bind-direct', async (req, res) => {
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
  } catch (err) { res.status(500).json({ success: false, message: "資料庫錯誤" }); }
});

app.get('/contacts/:userId', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT u.user_id as id, u.full_name as username, u.phone, u.role, c.id as connection_id, COALESCE(c.is_emergency, false) as is_emergency
       FROM connections c
       JOIN users u ON (u.user_id = c.blind_id OR u.user_id = c.caregiver_id)
       WHERE (c.blind_id = $1 OR c.caregiver_id = $1) AND u.user_id != $1 AND c.status = 'accepted'
       ORDER BY c.is_emergency DESC`, [req.params.userId]
    );
    res.json({ success: true, contacts: result.rows });
  } catch (err) { res.status(500).json({ success: false, error: "無法獲取聯絡人" }); }
});

app.post('/reject-bind', async (req, res) => {
  try {
    await db.query('DELETE FROM connections WHERE id = $1', [req.body.connectionId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false }); }
});

app.post('/set-emergency', async (req, res) => {
  const { blindId, connectionId } = req.body;
  try {
    await db.query('UPDATE connections SET is_emergency = false WHERE blind_id = $1', [blindId]);
    if (connectionId !== -1) {
      await db.query('UPDATE connections SET is_emergency = true WHERE id = $1', [connectionId]);
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
app.post('/sos', async (req, res) => {
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

app.get('/sos-history/:userId', async (req, res) => {
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
// 4. AI 辨識決策輔助與硬體資料接收
// ==========================================

// 啟動本機 Python AI 辨識程序（獨立子程序，透過 stdout/stderr 記錄執行狀況）
function startAIProcess() {
   console.log("[System] 正在啟動 Python AI 辨識模組...");
   // 使用絕對路徑，避免因執行目錄不同而找不到腳本檔案
   const scriptPath = path.join(__dirname, 'vision_ai.py');
   const pythonProcess = spawn('python', [scriptPath]);

    pythonProcess.stdout.on('data', (data) => {
        console.log(`[AI 輸出]: ${data.toString().trim()}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`[AI Error]: ${data.toString().trim()}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`[System] AI 進程已關閉，結束碼: ${code}`);
    });
}

// ESP32 硬體資料接收端點：接收距離與傾斜角度數據並寫入資料庫
app.post('/api/hardware', async (req, res) => {
    const { distance, tilt } = req.body;
    const time = new Date().toLocaleTimeString();

    if (distance === undefined || tilt === undefined) {
        return res.status(400).json({
            status: "error",
            message: "缺少必要數據" });
    }
    console.log(`[${time}] [硬體接收] 收到距離: ${distance}cm, 傾斜數據: ${tilt}`);

    try {
        await db.query('INSERT INTO hardware_logs(distance, tilt_angle) VALUES($1, $2)', [distance, tilt]);
        console.log(`[${time}] [硬體成功] 距離: ${distance}cm`);
        res.status(200).json({
            status: "success",
            message: "存檔成功"
        });
    } catch (err) {
        console.error('[DB Error]', err.message);
        res.status(500).json({
            status: "error",
            message: "資料庫寫入失敗"
        });
    }
});

// AI 影像辨識結果接收端點：接收已辨識完成的障礙物資訊，依規則判斷是否觸發警報
app.post('/api/vision', async (req, res) => {
    const { timestamp, gps, obstacle, distance } = req.body;

    if (!gps || !obstacle || distance === undefined) {
        return res.status(400).json({
            status: "error",
            message: "AI 傳來的數據不完整" });
    }

    const time = new Date().toLocaleTimeString();

    // 依決策規則判斷警報文字：僅回傳文字內容，語音播報交由前端處理
    let alertMessage = "環境安全";
    if (obstacle === '車' && distance < 100) {
        alertMessage = `警報:前方一公尺內有車輛 !`;
    }

    try {
        // 寫入影像辨識原始紀錄
        const queries = [
            db.query('INSERT INTO vision_logs(obstacle_type, distance_cm, gps_location) VALUES($1, $2, $3)', [obstacle, distance, gps])
        ];
        // 若判定有危險，額外寫入警報紀錄
        if (alertMessage !== "環境安全") {
            queries.push(
                db.query('INSERT INTO alert_logs(alert_text, source_type, gps_location) VALUES($1, $2, $3)', [alertMessage, 'AI_VISION', gps])
            );
        }

        await Promise.all(queries);
        // 回傳警報文字，前端使用 Expo-Speech 進行語音播報
        res.status(200).json({
            status: "success",
            alert: alertMessage,
            time: time
        });
    } catch (err) {
        console.error('[System Error]', err.message);
        res.status(500).json({
            status: "error",
            message: "處理失敗"
        });
    }
});

// ==========================================
// 5. 前端即時影像辨識：接收截圖，轉發給 Python 辨識後回傳結果
// ==========================================
app.post('/analyze', async (req, res) => {
    const { image, userId } = req.body;

    if (!image) {
        return res.status(400).json({ success: false, message: "未接收到影像數據" });
    }

    try {
        // 將前端傳來的 base64 圖片轉發給 Python AI 服務進行辨識
        // 注意：Python 端(YOLO+SegFormer)回傳的是 { objects: [...], analysis: [{object, distance, ratio}, ...] }
        // 而非單一 label/distance，這裡取 ratio 最大（最近）的物體作為代表性警示對象
        const aiResponse = await axios.post(PYTHON_AI_URL, { image, userId }, { timeout: 30000 });
        const { analysis } = aiResponse.data;

        if (!analysis || analysis.length === 0) {
            return res.status(200).json({ success: true, label: null, distance: null });
        }

        const closest = analysis.reduce((a, b) => (b.ratio > a.ratio ? b : a));
        // Python 的 distance 是「近 (Immediate)/中 (Medium)/遠 (Far)」字串，這裡取開頭中文字判斷等級
        const distance = closest.distance.startsWith('近') ? 'near'
            : closest.distance.startsWith('中') ? 'medium'
            : 'far';

        // label 直接使用 Python 已翻譯好的中文物體名稱（如「汽車」「人」），前端不需再對照字典
        res.status(200).json({ success: true, label: closest.object, distance });
    } catch (err) {
        console.error('[AI 辨識錯誤]', err.message);
        res.status(502).json({ success: false, message: "AI 辨識服務無法使用", label: null });
    }
});

// 啟動伺服器並監聽通訊埠
app.listen(PORT, () => {
    console.log(`[Server] 伺服器已啟動於 http://localhost:${PORT}`);
});
