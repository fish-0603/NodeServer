-- 新增 email 驗證機制：users.email_verified 標記該信箱是否已透過驗證碼確認擁有權，
-- email_verification_codes 存放寄出的驗證碼。
--
-- 動機：Google 登入若要用 email 比對既有帳密帳號並自動綁定登入，前提是那個 email
-- 必須「真的屬於這個人」，否則攻擊者可以搶先用受害者的 email 帳密註冊、等受害者
-- 用 Google 登入時被自動綁到攻擊者已知密碼的帳號。
--
-- 請用 psql / pgAdmin 對 App 這個資料庫執行一次：
--
--   psql -U postgres -d App -f migrations/007_add_email_verification.sql
--
-- 只新增欄位與資料表，不會刪除或修改任何既有資料。

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS email_verification_codes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS email_verification_codes_user_id_idx ON email_verification_codes(user_id);

-- 防止兩個「已驗證」帳號共用同一個 email；未驗證或 NULL 的 email 不受此限制，
-- 可以重複（例如多個帳號都還沒驗證同一個信箱）。
CREATE UNIQUE INDEX IF NOT EXISTS users_verified_email_idx ON users (email) WHERE email_verified = true;
