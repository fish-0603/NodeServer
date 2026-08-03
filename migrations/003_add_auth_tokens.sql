-- 新增 auth_tokens 表，供登入後簽發的 Bearer Token 使用。
-- 在此之前 API 只靠前端傳來的 userId 判斷身分，任何人都能冒用他人 ID 呼叫 API（IDOR）。
-- 請用 psql / pgAdmin 對 App 這個資料庫執行一次：
--
--   psql -U postgres -d App -f migrations/003_add_auth_tokens.sql
--
-- 只新增資料表，不會刪除或修改任何既有資料。

CREATE TABLE auth_tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX auth_tokens_user_id_idx ON auth_tokens(user_id);
