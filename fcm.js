// firebase-admin v14 起改用模組化 API（不再是 admin.credential.cert / admin.messaging()）
const path = require('path');
const { initializeApp, cert } = require('firebase-admin/app');
const { getMessaging } = require('firebase-admin/messaging');

// 服務帳戶金鑰不進版本控制（見 .gitignore 的 secrets/），預設放 secrets/firebase-adminsdk.json
const SERVICE_ACCOUNT_PATH = process.env.FIREBASE_SERVICE_ACCOUNT_PATH ||
  path.join(__dirname, 'secrets', 'firebase-adminsdk.json');

let messaging = null;
try {
  const serviceAccount = require(SERVICE_ACCOUNT_PATH);
  const app = initializeApp({ credential: cert(serviceAccount) });
  messaging = getMessaging(app);
  console.log('[FCM] Firebase Admin SDK 初始化成功');
} catch (err) {
  // 沒設定金鑰檔就跳過推播，不擋伺服器啟動
  console.error(`[FCM] 初始化失敗，推播通知將無法使用：${err.message}`);
}

// 個別 token 失效只記錄不拋例外，避免一台裝置的問題擋到其他照護者收到通知
async function sendPushToTokens(tokens, notification, data = {}) {
  if (!messaging || tokens.length === 0) return;
  try {
    const result = await messaging.sendEachForMulticast({
      tokens,
      notification,
      data,
      android: { priority: 'high' },
    });
    if (result.failureCount > 0) {
      result.responses.forEach((r, i) => {
        if (!r.success) console.error(`[FCM] 發送給 token ${tokens[i]} 失敗：${r.error?.message}`);
      });
    }
  } catch (err) {
    console.error('[FCM] 推播發送失敗:', err.message);
  }
}

module.exports = { sendPushToTokens };
