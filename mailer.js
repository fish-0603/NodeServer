// 用 Gmail SMTP 寄送 email 驗證碼。免費額度（一般 Gmail 帳號約每日 500 封）對這個規模的
// 系統綽綽有餘，不需要付費的轉寄信服務。
const nodemailer = require('nodemailer');

const GMAIL_USER = process.env.GMAIL_USER || '';
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || '';

let transporter = null;
if (GMAIL_USER && GMAIL_APP_PASSWORD) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
  });
  console.log('[Mailer] Gmail SMTP 初始化成功');
} else {
  // 沒設定帳密就跳過寄信功能，不擋伺服器啟動（跟 fcm.js 沒設服務帳戶金鑰時的降級處理一致）
  console.error('[Mailer] 未設定 GMAIL_USER / GMAIL_APP_PASSWORD，email 驗證信將無法寄送');
}

async function sendVerificationEmail(to, code) {
  if (!transporter) return;
  try {
    await transporter.sendMail({
      from: `SmartGuide <${GMAIL_USER}>`,
      to,
      subject: 'SmartGuide 電子郵件驗證碼',
      text: `您的驗證碼是：${code}\n\n此驗證碼將於 15 分鐘後失效。如果不是您本人操作，請忽略這封信。`,
    });
  } catch (err) {
    console.error('[Mailer] 寄送驗證信失敗:', err.message);
  }
}

module.exports = { sendVerificationEmail };
