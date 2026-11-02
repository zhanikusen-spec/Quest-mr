'use strict';
/*
  VR Box · Quest — сервер
  • раздаёт игру (index.html рядом с server.js)
  • регистрация / вход / облачное сохранение  (POST /api/...)
  • онлайн: игроки с никами над головой + голос по радиусу (WebSocket)
*/
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'accounts.json');
const INDEX_FILE = path.join(__dirname, 'index.html');
const MAX_PER_ROOM = Number(process.env.MAX_PER_ROOM) || 12; // игроков в одной комнате (id < 256)
const VOICE_R = 12;                                            // радиус слышимости голоса, м
const NICK_RE = /^[A-Za-z0-9_\-А-Яа-яЁё]{3,16}$/;
const MAX_DATA = 64 * 1024;                                    // максимум облачного сохранения

/* ---------------- база аккаунтов (JSON-файл) ---------------- */
let users = {};          // ключ = ник в нижнем регистре
const tokenIndex = {};   // sha256(token) -> ключ ника
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (fs.existsSync(DB_FILE)) users = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
} catch (e) { console.error('Не смог прочитать базу:', e.message); users = {}; }
for (const k in users) for (const h of users[k].tokens || []) tokenIndex[h] = k;

let saveTimer = null;
function saveDB(now) {
  if (now) { clearTimeout(saveTimer); saveTimer = null; return flush(); }
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; flush(); }, 1500);
}
function flush() {
  try {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(users));
    fs.renameSync(tmp, DB_FILE);
  } catch (e) { console.error('Ошибка записи базы:', e.message); }
}
process.on('SIGTERM', () => { flush(); process.exit(0); });
process.on('SIGINT', () => { flush(); process.exit(0); });

const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 32, (e, k) => e ? rej(e) : res(k.toString('hex'))));

function newToken(u, key) {
  const token = crypto.randomBytes(32).toString('hex');
  const h = sha(token);
  u.tokens = u.tokens || [];
  u.tokens.push(h);
  while (u.tokens.length > 5) delete tokenIndex[u.tokens.shift()];
  tokenIndex[h] = key;
  return token;
}
function userByToken(token) {
  if (typeof token !== 'string' || token.length !== 64) return null;
  const key = tokenIndex[sha(token)];
  return key && users[key] ? users[key] : null;
}
function cleanData(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
  const s = JSON.stringify(d);
  if (s.length > MAX_DATA) return null;
  return JSON.parse(s);
}

/* ---------------- ограничение частоты ---------------- */
const hits = new Map();
function limited(ip, max = 15, win = 60000) {
  const now = Date.now();
  let h = hits.get(ip);
  if (!h || now > h.t) { h = { n: 0, t: now + win }; hits.set(ip, h); }
  return ++h.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (n > v.t) hits.delete(k); }, 60000).unref();

/* ---------------- HTTP ---------------- */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.mp3': 'audio/mpeg',
  '.wasm': 'application/wasm', '.glb': 'model/gltf-binary'
};
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};
const send = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json', ...CORS });
  res.end(JSON.stringify(obj));
};
const ipOf = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();

function readBody(req) {
  return new Promise((res, rej) => {
    let n = 0; const ch = [];
    req.on('data', c => { n += c.length; if (n > 256 * 1024) { rej(new Error('big')); req.destroy(); } else ch.push(c); });
    req.on('end', () => { try { res(JSON.parse(Buffer.concat(ch).toString() || '{}')); } catch (e) { rej(new Error('json')); } });
    req.on('error', rej);
  });
}

async function api(req, res, url) {
  let b;
  try { b = await readBody(req); } catch (e) { return send(res, 400, { error: 'Плохой запрос' }); }
  const ip = ipOf(req);

  if (url === '/api/register') {
    if (limited(ip)) return send(res, 429, { error: 'Слишком много попыток, подожди минуту' });
    const nick = String(b.nick || '').trim(), pass = String(b.pass || '');
    if (!NICK_RE.test(nick)) return send(res, 400, { error: 'Ник: 3–16 символов, буквы, цифры, _ и -' });
    if (pass.length < 4 || pass.length > 64) return send(res, 400, { error: 'Пароль: от 4 символов' });
    const key = nick.toLowerCase();
    if (users[key]) return send(res, 409, { error: 'Такой ник уже занят' });
    const salt = crypto.randomBytes(16).toString('hex');
    const u = { nick, salt, hash: await scrypt(pass, salt), tokens: [], data: cleanData(b.data), created: Date.now() };
    if (users[key]) return send(res, 409, { error: 'Такой ник уже занят' });
    users[key] = u;
    const token = newToken(u, key);
    saveDB();
    return send(res, 200, { nick, token, data: u.data });
  }

  if (url === '/api/login') {
    if (limited(ip)) return send(res, 429, { error: 'Слишком много попыток, подожди минуту' });
    const key = String(b.nick || '').trim().toLowerCase(), u = users[key];
    const hash = u ? await scrypt(String(b.pass || ''), u.salt) : null;
    if (!u || !crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(u.hash)))
      return send(res, 401, { error: 'Неверный ник или пароль' });
    const token = newToken(u, key);
    saveDB();
    return send(res, 200, { nick: u.nick, token, data: u.data });
  }

  if (url === '/api/me') {
    const u = userByToken(b.token);
    if (!u) return send(res, 401, { error: 'Аккаунт не найден' });
    return send(res, 200, { nick: u.nick, data: u.data });
  }

  if (url === '/api/save') {
    if (limited(ip + ':s', 120)) return send(res, 429, { error: 'Слишком часто' });
    const u = userByToken(b.token);
    if (!u) return send(res, 401, { error: 'Аккаунт не найден' });
    const d = cleanData(b.data);
    if (!d) return send(res, 400, { error: 'Плохие данные' });
    u.data = d;
    saveDB();
    return send(res, 200, { ok: true });
  }

  send(res, 404, { error: 'Нет такого' });
}

const cache = new Map(); // файл -> {mtime, gz}
// Всё лежит в одной папке, поэтому отдаём наружу ТОЛЬКО index.html (server.js и data остаются закрытыми)
function serveStatic(req, res, url) {
  const p = decodeURIComponent(url.split('?')[0]);
  if (p !== '/' && p !== '/index.html') { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Не найдено'); }
  const file = INDEX_FILE;
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('index.html не найден рядом с server.js'); }
    const h = { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-cache' };
    if (!/\bgzip\b/.test(req.headers['accept-encoding'] || '')) { res.writeHead(200, { ...h, 'Content-Length': st.size }); return fs.createReadStream(file).pipe(res); }
    let c = cache.get(file);
    if (!c || c.mtime !== st.mtimeMs) { c = { mtime: st.mtimeMs, gz: zlib.gzipSync(fs.readFileSync(file), { level: 6 }) }; cache.set(file, c); }
    res.writeHead(200, { ...h, 'Content-Encoding': 'gzip', 'Content-Length': c.gz.length, Vary: 'Accept-Encoding' });
    res.end(c.gz);
  });
}

const server = http.createServer((req, res) => {
  const url = req.url || '/';
  if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
  if (url === '/health') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
  if (req.method === 'POST' && url.startsWith('/api/')) {
    return api(req, res, url.split('?')[0]).catch(e => { console.error(e); send(res, 500, { error: 'Ошибка сервера' }); });
  }
  if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, url);
  res.writeHead(405); res.end();
});

/* ---------------- онлайн (WebSocket) ---------------- */
const rooms = new Map(); // номер комнаты -> Set<клиент>
const byNick = new Map(); // ник(lower) -> клиент

const wss = new WebSocketServer({ server, maxPayload: 32 * 1024 });

function freeId(set) {
  const used = new Set([...set].map(c => c.id));
  for (let i = 1; i < 256; i++) if (!used.has(i)) return i;
  return 0;
}
const num = (v, lim = 2000) => (typeof v === 'number' && isFinite(v)) ? Math.max(-lim, Math.min(lim, v)) : 0;

function leave(c) {
  if (c.room) {
    const set = rooms.get(c.room);
    if (set) { set.delete(c); if (!set.size) rooms.delete(c.room); }
    c.room = 0;
  }
  if (c.key && byNick.get(c.key) === c) byNick.delete(c.key);
}

wss.on('connection', ws => {
  const c = { ws, id: 0, room: 0, nick: '', key: '', has: false, x: 0, y: 0, z: 0, r: 0, h: '', m: 0, alive: true, vt: 0, vn: 0 };
  const joinTimer = setTimeout(() => { if (!c.room) ws.close(); }, 10000);

  ws.on('pong', () => { c.alive = true; });

  ws.on('message', (data, isBinary) => {
    /* голос: [PCM int16, 8 кГц] -> ближним игрокам: [id][PCM] */
    if (isBinary) {
      if (!c.room || data.length < 4 || data.length > 8192) return;
      const now = Date.now();
      if (now - c.vt > 1000) { c.vt = now; c.vn = 0; }
      if (++c.vn > 120) return;
      const set = rooms.get(c.room);
      if (!set) return;
      const out = Buffer.concat([Buffer.from([c.id]), data]);
      for (const o of set) {
        if (o === c || o.ws.readyState !== 1 || o.ws.bufferedAmount > 262144) continue;
        if (Math.hypot(o.x - c.x, o.y - c.y, o.z - c.z) <= VOICE_R) o.ws.send(out, { binary: true });
      }
      return;
    }

    let m;
    try { m = JSON.parse(data.toString()); } catch (e) { return; }

    if (m.t === 'join' && !c.room) {
      const u = userByToken(m.token);
      if (!u) { ws.send(JSON.stringify({ t: 'auth' })); return ws.close(); }
      const room = Math.floor(Number(m.room));
      if (!(room >= 1 && room <= 99)) return ws.close();
      const key = u.nick.toLowerCase();
      const old = byNick.get(key);                 // один аккаунт = одно подключение
      if (old && old !== c) { try { old.ws.send(JSON.stringify({ t: 'kick' })); old.ws.close(); } catch (e) { } leave(old); }
      let set = rooms.get(room);
      if (!set) { set = new Set(); rooms.set(room, set); }
      if (set.size >= MAX_PER_ROOM) { ws.send(JSON.stringify({ t: 'full' })); return ws.close(); }
      c.id = freeId(set);
      if (!c.id) { ws.send(JSON.stringify({ t: 'full' })); return ws.close(); }
      c.room = room; c.nick = u.nick; c.key = key;
      set.add(c); byNick.set(key, c);
      clearTimeout(joinTimer);
      ws.send(JSON.stringify({ t: 'hello', id: c.id, nick: c.nick }));
      return;
    }

    if (m.t === 'pos' && c.room) {
      c.x = num(m.x); c.y = num(m.y); c.z = num(m.z); c.r = num(m.r, 10);
      c.h = typeof m.h === 'string' ? m.h.slice(0, 24) : '';
      c.m = m.m ? 1 : 0;
      c.has = true;
    }
  });

  ws.on('close', () => { clearTimeout(joinTimer); leave(c); });
  ws.on('error', () => { });
});

/* 10 раз в секунду рассылаем всем, кто где стоит */
setInterval(() => {
  for (const set of rooms.values()) {
    const list = [];
    for (const c of set) if (c.has) list.push({ i: c.id, u: c.nick, x: c.x, y: c.y, z: c.z, r: c.r, h: c.h, m: c.m });
    for (const c of set) {
      if (c.ws.readyState !== 1 || c.ws.bufferedAmount > 1048576) continue;
      c.ws.send(JSON.stringify({ t: 'state', n: set.size, p: list.filter(p => p.i !== c.id) }));
    }
  }
}, 100);

/* убираем «зависшие» подключения (телефон уснул) */
setInterval(() => {
  for (const set of rooms.values()) for (const c of set) {
    if (!c.alive) { c.ws.terminate(); continue; }
    c.alive = false;
    try { c.ws.ping(); } catch (e) { }
  }
}, 25000).unref();

server.listen(PORT, () => console.log('VR Box сервер запущен на порту ' + PORT + ', данные: ' + DATA_DIR));
