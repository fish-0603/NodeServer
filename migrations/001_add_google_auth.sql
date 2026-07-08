-- Google 登入所需的資料庫變更
-- 請用 psql / pgAdmin 對 App 這個資料庫執行一次
--
--   psql -U postgres -d App -f migrations/001_add_google_auth.sql
--
-- 這個 migration 只會新增欄位、放寬既有欄位的限制，不會刪除或修改任何既有資料。

ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(20) NOT NULL DEFAULT 'local';

-- Google 登入的帳號沒有密碼，password_hash 必須允許 NULL
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
