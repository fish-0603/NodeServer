require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'App',
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});

// node-postgres 在閒置連線發生錯誤時（例如資料庫重啟、網路中斷）會在 pool 上發出 'error' 事件，
// 沒有監聽的話會變成未處理的例外，直接把整個 Node process 弄掛，而不是只影響那一次查詢
pool.on('error', (err) => {
  console.error('[DB Pool Error]', err.message);
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool,
};
