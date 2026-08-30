-- 移除 users.auth_provider 欄位。
--
-- 這欄位從加入以來只有在建立 Google 帳號時被寫入，程式碼裡沒有任何查詢會讀取它
-- （判斷「這帳號是不是 Google 登入」實際上是用 password_hash IS NULL），是個沒有
-- 驅動任何邏輯的死欄位，砍掉不影響任何功能。
--
-- 請用 psql / pgAdmin 對 App 這個資料庫執行一次：
--
--   psql -U postgres -d App -f migrations/008_drop_auth_provider.sql

ALTER TABLE users DROP COLUMN IF EXISTS auth_provider;
