-- alert_logs 是 database_schema.sql 裡定義的舊表，但目前 index.js 沒有任何路由讀寫它
-- （SOS 警報實際存在 sos_events，AI 辨識結果存在 vision_logs），已確認資料表是空的，刪除不會遺失資料。
-- 請用 psql / pgAdmin 對 App 這個資料庫執行一次：
--
--   psql -U postgres -d App -f migrations/004_drop_alert_logs.sql

DROP TABLE IF EXISTS alert_logs;
