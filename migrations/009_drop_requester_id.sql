-- 移除 connections.requester_id 欄位。
--
-- 目前唯一的綁定入口 /bind-direct 只由照護者端（caregiver/bind.tsx）呼叫，
-- 且 requireSelf('myId') 中介層強制要求 myId 等於呼叫者自己的身分，所以
-- requester_id 寫進去的值永遠等於 caregiver_id，是完全重複的資訊，程式碼裡
-- 也沒有任何查詢讀取過這欄。
--
-- 順便清掉一個不一致之處：這欄的外鍵沒有設 ON DELETE CASCADE（跟 blind_id/
-- caregiver_id 不一樣），砍掉這欄也一併移除這個風險。
--
-- 請用 psql / pgAdmin 對 App 這個資料庫執行一次：
--
--   psql -U postgres -d App -f migrations/009_drop_requester_id.sql

ALTER TABLE connections DROP COLUMN IF EXISTS requester_id;
