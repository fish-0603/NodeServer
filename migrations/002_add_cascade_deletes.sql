-- 補上 database.sql 原本就定義、但目前資料庫外鍵漏掉的 ON DELETE CASCADE
-- 請用 psql / pgAdmin 對 App 這個資料庫執行一次
--
--   psql -U postgres -d App -f migrations/002_add_cascade_deletes.sql
--
-- 只調整刪除規則，不會刪除或修改任何既有資料。
-- requester_id 維持原樣（database.sql 裡本來就沒有 CASCADE）。

ALTER TABLE connections DROP CONSTRAINT connections_blind_id_fkey;
ALTER TABLE connections ADD CONSTRAINT connections_blind_id_fkey
  FOREIGN KEY (blind_id) REFERENCES users(user_id) ON DELETE CASCADE;

ALTER TABLE connections DROP CONSTRAINT connections_caregiver_id_fkey;
ALTER TABLE connections ADD CONSTRAINT connections_caregiver_id_fkey
  FOREIGN KEY (caregiver_id) REFERENCES users(user_id) ON DELETE CASCADE;

ALTER TABLE sos_events DROP CONSTRAINT sos_events_user_id_fkey;
ALTER TABLE sos_events ADD CONSTRAINT sos_events_user_id_fkey
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE;
