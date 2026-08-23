-- vision_logs 原本是 PythonServer 每次辨識完非同步回呼 /api/result 寫入的「最近物體」備份紀錄，
-- 但這張表從頭到尾只有寫入、沒有任何路由讀取過（不像 sos_events 有 /sos-history 顯示給照護者看），
-- 純粹是沒人用的紀錄。已經把 NodeServer 的 /api/result 端點跟 PythonServer 那邊的非同步回呼都拿掉了，
-- 這張表不會再有新資料寫入，故一併刪除。
--
-- 注意：這張表刪除前已經有歷史資料（不是空表），DROP TABLE 會連同這些資料一起清掉，
-- 如果需要保留歷史紀錄，請先自行備份（例如 pg_dump -t vision_logs）再執行這份 migration。
--
--   psql -U postgres -d App -f migrations/006_drop_vision_logs.sql

DROP TABLE IF EXISTS vision_logs;
