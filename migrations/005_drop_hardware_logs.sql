-- hardware_logs 是 database_schema.sql 裡定義的舊表，原本預留給 ESP32 硬體回報距離／傾斜角度用，
-- 但 /api/hardware 這支端點從初版建置以來就沒有任何呼叫端（App、韌體都沒有接），已確認資料表是空的，刪除不會遺失資料。
-- 請用 psql / pgAdmin 對 App 這個資料庫執行一次：
--
--   psql -U postgres -d App -f migrations/005_drop_hardware_logs.sql

DROP TABLE IF EXISTS hardware_logs;
