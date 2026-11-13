// S02E05 away agent: takes signed course POSTs, does free acts alone, holds gated acts for the owner.
import http from 'node:http';
import crypto from 'node:crypto';
import { check, DEFAULT_POLICY } from './policy.mjs';

const PORT = Number(process.env.PORT || 3000);
const OWNER_SECRET = process.env.OWNER_SECRET || '';
const NTFY_TOPIC = process.env.NTFY_TOPIC || '';
const NTFY_SERVER = process.env.NTFY_SERVER || 'https://ntfy.sh';
const PUBLIC_URL = (process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const COURSE_HOSTS = (process.env.COURSE_HOSTS || 'hq.mega.dev').split(',').map(s => s.trim()).filter(Boolean);
const HOLD_MS = 60 * 60 * 1000;
let signingKey = process.env.SIGNING_KEY || '';

const ACT_TEXT = {
  post_status: 'posted the status line to the team channel',
  ack_alert: 'acknowledged the open alert',
  archive_report: 'moved the report into the archive',
  purge_cache: 'cleared the build cache',
  release_hold: 'released the held deploy to production',
  rotate_key: 'rotated the shared API key',
};

const events = [];           // what happened, newest last (owner-only view)
const seen = new Set();      // signatures already handled (replay guard)
const pending = [];          // raw messages that came before the signing key was known
const holds = new Map();     // id -> hold

function log(kind, data) {
  const e = { at: new Date().toISOString(), kind, ...data };
  events.push(e); if (events.length > 500) events.shift();
  console.log(JSON.stringify(e));
}

const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const ownerOk = req => OWNER_SECRET && eq((req.headers.authorization || '').replace(/^Bearer /, ''), OWNER_SECRET);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function verify(ts, sig, raw) {
  if (!signingKey || !ts || !sig) return false;
  const want = 'sha256=' + crypto.createHmac('sha256', signingKey).update(`${ts}.${raw}`).digest('hex');
  return eq(sig, want);
}

function freshTs(ts) {
  const n = Number(ts); if (!Number.isFinite(n)) return false;
  const ms = n > 1e12 ? n : n * 1000;
  return Math.abs(Date.now() - ms) < 10 * 60 * 1000;
}

function replyUrlOk(u) {
  if (process.env.TEST_REPLY_ANY === '1') return true;
  try { const x = new URL(u); return x.protocol === 'https:' && COURSE_HOSTS.some(h => x.hostname === h || x.hostname.endsWith('.' + h)); }
  catch { return false; }
}

async function reply(replyUrl, text, ref) {
  if (!replyUrlOk(replyUrl)) { log('reply_blocked', { ref, replyUrl }); return; }
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(replyUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text }) });
      const body = (await r.text()).slice(0, 500);
      log('reply', { ref, status: r.status, text, body });
      if (r.ok) return;
    } catch (e) { log('reply_error', { ref, error: String(e) }); }
    await new Promise(r => setTimeout(r, 2000 * (i + 1)));
  }
}

async function ping(title, message, click) {
  if (!NTFY_TOPIC) { log('ping_skipped', { title }); return; }
  try {
    const r = await fetch(`${NTFY_SERVER}/${encodeURIComponent(NTFY_TOPIC)}`, {
      method: 'POST',
      headers: { Title: title, Priority: 'high', Tags: 'warning', ...(click ? { Click: click, Actions: `view, Open, ${click}` } : {}) },
      body: message,
    });
    log('ping', { title, status: r.status });
  } catch (e) { log('ping_error', { error: String(e) }); }
}

function doAct(act, ref) { log('act_done', { ref, act }); return ACT_TEXT[act] || `did ${act}`; }

async function handle(post, ref) {
  const { from, subject, text, replyUrl } = post || {};
  const r = check(text, DEFAULT_POLICY);
  log('message', { ref, from, subject, text, acts: r.acts, label: r.label, reason: r.reason });
  if (r.acts.length === 0) { await reply(replyUrl, 'UP: received. No act asked, so I did nothing.', ref); return; }
  const free = r.acts.filter(a => DEFAULT_POLICY[a] === 'free');
  const gated = r.acts.filter(a => DEFAULT_POLICY[a] !== 'free');
  free.forEach(a => doAct(a, ref));
  const lines = r.acts.map(a => (gated.includes(a) ? 'HOLD: ' : 'DONE: ') + a);
  await reply(replyUrl, lines.join('\n'), ref);
  if (!gated.length) return;
  const id = crypto.randomBytes(6).toString('hex');
  const token = crypto.randomBytes(18).toString('base64url');
  const hold = { id, token, ref, from, subject, text, replyUrl, acts: gated, reason: r.reason, at: Number(post.heldSince) || Date.now(), state: 'held' };
  holds.set(id, hold);
  await ping(`Held: ${gated.join(', ')}`, `${from || 'course'}: ${String(text).slice(0, 300)}\nOpen to approve with your code.`, `${PUBLIC_URL}/hold/${id}?t=${token}`);
  setTimeout(() => { if (hold.state === 'held') { hold.state = 'expired'; log('hold_expired', { ref, id }); } }, HOLD_MS).unref();
}

function process_(raw, headers, ref) {
  const ts = headers['x-course-timestamp'], sig = headers['x-course-signature'];
  if (!verify(ts, sig, raw)) { log('bad_signature', { ref }); return; }
  if (!freshTs(ts)) { log('stale_timestamp', { ref, ts }); return; }
  if (seen.has(sig)) { log('replay', { ref }); return; }
  seen.add(sig);
  let post; try { post = JSON.parse(raw); } catch { log('bad_json', { ref }); return; }
  handle(post, ref).catch(e => log('handle_error', { ref, error: String(e) }));
}

function holdPage(h, note = '') {
  const open = h.state === 'held';
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Held act</title><style>body{font:16px system-ui;margin:0 auto;max-width:520px;padding:16px}pre{white-space:pre-wrap;background:#f3f3f3;padding:12px;border-radius:8px}input,button{font:inherit;padding:10px;width:100%;box-sizing:border-box;margin:6px 0}button.no{background:#fff}</style>
<h2>Held: ${esc(h.acts.join(', ') || 'request')}</h2>
<p>From <b>${esc(h.from)}</b> — ${esc(h.subject)}<br><small>${new Date(h.at).toISOString()} · state: <b>${esc(h.state)}</b></small></p>
<pre>${esc(h.text)}</pre>${note ? `<p><b>${esc(note)}</b></p>` : ''}
${open ? `<form method="post"><input type="hidden" name="t" value="${esc(h.token)}">
<label>Your code<input name="code" autocomplete="one-time-code" required></label>
<button name="decision" value="approve">Approve and do it</button></form>
<form method="post"><input type="hidden" name="t" value="${esc(h.token)}"><input type="hidden" name="code" value="-">
<button class="no" name="decision" value="deny">Deny</button></form>` : ''}`;
}

async function readBody(req, limit = 256 * 1024) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > limit) throw new Error('too big'); chunks.push(c); }
  return Buffer.concat(chunks).toString('utf8');
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const send = (code, body, type = 'application/json') => { res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store' }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
  try {
    if (req.method === 'GET' && url.pathname === '/health') return send(200, { ok: true, signingKey: !!signingKey, ntfy: !!NTFY_TOPIC, held: [...holds.values()].filter(h => h.state === 'held').length });

    if (req.method === 'POST' && url.pathname === '/course') {
      const raw = await readBody(req);
      const ref = crypto.randomBytes(4).toString('hex');
      send(202, { ok: true });
      const headers = { 'x-course-timestamp': req.headers['x-course-timestamp'], 'x-course-signature': req.headers['x-course-signature'] };
      log('received', { ref, bytes: raw.length });
      if (!signingKey) { pending.push({ raw, headers, ref }); log('queued_no_key', { ref }); return; }
      return process_(raw, headers, ref);
    }

    if (url.pathname.startsWith('/hold/')) {
      const h = holds.get(url.pathname.slice(6));
      if (!h) return send(404, 'not found', 'text/plain');
      if (req.method === 'GET') {
        if (!eq(url.searchParams.get('t') || '', h.token)) return send(403, 'forbidden', 'text/plain');
        return send(200, holdPage(h), 'text/html; charset=utf-8');
      }
      if (req.method === 'POST') {
        const f = new URLSearchParams(await readBody(req, 8192));
        if (!eq(f.get('t') || '', h.token)) return send(403, 'forbidden', 'text/plain');
        if (h.state !== 'held') return send(409, holdPage(h, 'Already ' + h.state), 'text/html; charset=utf-8');
        const code = (f.get('code') || '').trim();
        if (f.get('decision') === 'deny') {
          h.state = 'denied'; log('hold_denied', { ref: h.ref, id: h.id });
          await reply(h.replyUrl, h.acts.map(a => `DECLINED: ${a}`).join('\n'), h.ref);
          return send(200, holdPage(h, 'Denied. The course was told.'), 'text/html; charset=utf-8');
        }
        if (!code || code.length > 64) return send(400, holdPage(h, 'Enter the code.'), 'text/html; charset=utf-8');
        h.state = 'approved'; log('hold_approved', { ref: h.ref, id: h.id, codeLen: code.length });
        h.acts.forEach(a => doAct(a, h.ref));
        await reply(h.replyUrl, h.acts.map(a => `DONE: ${a} CODE: ${code}`).join('\n'), h.ref);
        return send(200, holdPage(h, 'Approved. Done and reported.'), 'text/html; charset=utf-8');
      }
    }

    if (url.pathname.startsWith('/admin/')) {
      if (!ownerOk(req)) return send(401, { error: 'owner only' });
      if (req.method === 'POST' && url.pathname === '/admin/signing-key') {
        const { key } = JSON.parse(await readBody(req, 4096) || '{}');
        if (!key) return send(400, { error: 'key missing' });
        signingKey = String(key); log('signing_key_set', { len: signingKey.length });
        const q = pending.splice(0); q.forEach(p => process_(p.raw, p.headers, p.ref));
        return send(200, { ok: true, replayed: q.length });
      }
      if (req.method === 'POST' && url.pathname === '/admin/refeed') {
        const post = JSON.parse(await readBody(req, 65536));
        const ref = 'refeed-' + crypto.randomBytes(3).toString('hex');
        handle(post, ref).catch(e => log('handle_error', { ref, error: String(e) }));
        return send(202, { ok: true, ref });
      }
      if (req.method === 'GET' && url.pathname === '/admin/events') return send(200, { events, holds: [...holds.values()].map(({ token, ...h }) => h) });
      if (req.method === 'GET' && url.pathname === '/admin/holds') return send(200, [...holds.values()].filter(h => h.state === 'held').map(h => ({ id: h.id, acts: h.acts, link: `${PUBLIC_URL}/hold/${h.id}?t=${h.token}` })));
      if (req.method === 'POST' && url.pathname === '/admin/test-ping') { await ping('Test from your away agent', 'If you see this, pings reach your phone.', `${PUBLIC_URL}/health`); return send(200, { ok: true }); }
    }
    send(404, { error: 'not found' });
  } catch (e) { log('server_error', { error: String(e) }); if (!res.headersSent) send(500, { error: 'server error' }); }
});

server.listen(PORT, () => log('start', { port: PORT, publicUrl: PUBLIC_URL, ownerSecret: !!OWNER_SECRET, ntfy: !!NTFY_TOPIC }));

// Render free sleeps after 15 min without inbound traffic: knock on our own public door every 5 min.
if (process.env.SELF_PING !== '0' && /^https:/.test(PUBLIC_URL)) {
  setInterval(() => fetch(`${PUBLIC_URL}/health`).catch(() => {}), 5 * 60 * 1000).unref?.();
}
