// Family Book API: one Vercel function. Firestore is reached with the service account over REST, so the
// browser never talks to the database and Aadhaar numbers are filtered here, on the server.
'use strict';
const crypto = require('crypto');

const FAMILY_CODE = () => String(process.env.FAMILY_CODE || '');
const ADMIN_PASSWORD = () => String(process.env.ADMIN_PASSWORD || '');
const SECRET = () => String(process.env.TOKEN_SECRET || '');
const DAY = 86400000;
const BLOODS = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'];

/* ---------- storage: Firestore REST, or memory when FB_MOCK=1 (tests) ---------- */
const mem = { people: new Map(), members: new Map() };
let gtok = { v: '', exp: 0 };
function b64u(b) { return Buffer.from(b).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
async function googleToken() {
  if (gtok.v && Date.now() < gtok.exp - 60000) return gtok.v;
  const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
  if (!sa.client_email || !sa.private_key) throw new Error('FIREBASE_SERVICE_ACCOUNT is missing or invalid');
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64u(JSON.stringify({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 }));
  const sig = crypto.createSign('RSA-SHA256').update(head + '.' + claim).sign(sa.private_key);
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + head + '.' + claim + '.' + b64u(sig)
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('Google auth failed');
  gtok = { v: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return gtok.v;
}
function base() {
  const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
  const pid = process.env.FIREBASE_PROJECT_ID || sa.project_id;
  return 'projects/' + pid + '/databases/(default)/documents';
}
function enc(o) {
  const f = {};
  Object.keys(o).forEach(k => { const v = o[k]; f[k] = typeof v === 'number' ? { integerValue: String(Math.round(v)) } : { stringValue: String(v) }; });
  return f;
}
function dec(doc) {
  const o = {};
  Object.keys(doc.fields || {}).forEach(k => { const v = doc.fields[k]; o[k] = v.stringValue !== undefined ? v.stringValue : (v.integerValue !== undefined ? Number(v.integerValue) : ''); });
  return o;
}
async function fsFetch(url, opt) {
  const t = await googleToken();
  const r = await fetch('https://firestore.googleapis.com/v1/' + url, Object.assign({ headers: { Authorization: 'Bearer ' + t, 'Content-Type': 'application/json' } }, opt));
  if (r.status === 404) return null;
  const j = await r.json();
  if (!r.ok) throw new Error('Firestore ' + r.status + ': ' + ((j.error && j.error.message) || ''));
  return j;
}
const store = {
  async get(col, id) {
    if (process.env.FB_MOCK) return (mem[col].get(id) || null);
    const d = await fsFetch(base() + '/' + col + '/' + id);
    return d ? dec(d) : null;
  },
  async list(col) {
    if (process.env.FB_MOCK) return Array.from(mem[col].entries()).map(([id, v]) => Object.assign({ _id: id }, v));
    const out = []; let tok = '';
    do {
      const d = await fsFetch(base() + '/' + col + '?pageSize=300' + (tok ? '&pageToken=' + encodeURIComponent(tok) : ''));
      if (!d) break;
      (d.documents || []).forEach(x => out.push(Object.assign({ _id: x.name.split('/').pop() }, dec(x))));
      tok = d.nextPageToken || '';
    } while (tok);
    return out;
  },
  async commit(writes) {
    if (!writes.length) return;
    if (process.env.FB_MOCK) { writes.forEach(w => { if (w.op === 'del') mem[w.col].delete(w.id); else mem[w.col].set(w.id, Object.assign({}, w.obj)); }); return; }
    for (let i = 0; i < writes.length; i += 400) {
      const part = writes.slice(i, i + 400).map(w => w.op === 'del'
        ? { delete: base() + '/' + w.col + '/' + w.id }
        : { update: { name: base() + '/' + w.col + '/' + w.id, fields: enc(w.obj) } });
      await fsFetch(base() + ':commit', { method: 'POST', body: JSON.stringify({ writes: part }) });
    }
  }
};

/* ---------- helpers ---------- */
function safeEq(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest(), y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}
function sign(payload) {
  const p = b64u(JSON.stringify(payload));
  return p + '.' + b64u(crypto.createHmac('sha256', SECRET()).update(p).digest());
}
function verify(tok) {
  if (!tok || typeof tok !== 'string' || !SECRET()) return null;
  const i = tok.indexOf('.');
  if (i < 1) return null;
  const p = tok.slice(0, i), s = tok.slice(i + 1);
  const good = b64u(crypto.createHmac('sha256', SECRET()).update(p).digest());
  if (s.length !== good.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(good))) return null;
  try {
    const d = JSON.parse(Buffer.from(p.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    return d && d.e > Date.now() ? d : null;
  } catch (e) { return null; }
}
const normName = n => String(n || '').normalize('NFC').trim().replace(/\s+/g, ' ').toLowerCase().slice(0, 60);
const memberId = n => crypto.createHash('sha256').update('fb:' + normName(n)).digest('hex').slice(0, 24);
function hashPin(pin, salt) {
  salt = salt || crypto.randomBytes(12).toString('hex');
  return salt + ':' + crypto.scryptSync(String(pin), salt, 32).toString('hex');
}
function checkPin(pin, stored) {
  const i = String(stored || '').indexOf(':');
  if (i < 1) return false;
  const h = hashPin(pin, stored.slice(0, i));
  return safeEq(h, stored);
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
const hits = new Map();
function throttled(ip) {
  const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 600000);
  a.push(now); hits.set(ip, a);
  return a.length > 60;
}

/* ---------- people ---------- */
const s = (v, n) => (typeof v === 'string' ? v : (v === null || v === undefined ? '' : String(v))).slice(0, n || 200);
function cleanPerson(x) {
  const date = v => (/^\d{4}-\d{2}-\d{2}$/.test(s(v, 10)) ? v : '');
  return {
    id: s(x.id, 64),
    name: s(x.name, 100).trim(),
    gender: ['M', 'F', 'O'].includes(x.gender) ? x.gender : '',
    dob: date(x.dob),
    dobYear: /^\d{4}$/.test(s(x.dobYear, 4)) ? x.dobYear : '',
    dead: !!x.dead,
    dod: date(x.dod),
    phone: s(x.phone, 30).trim(),
    aadhaar: s(x.aadhaar, 20).replace(/\D/g, '').slice(0, 12),
    blood: BLOODS.includes(x.blood) ? x.blood : '',
    fatherId: s(x.fatherId, 64),
    motherId: s(x.motherId, 64),
    spouseIds: (Array.isArray(x.spouseIds) ? x.spouseIds : []).filter(i => typeof i === 'string' && i && i.length <= 64).slice(0, 12),
    notes: s(x.notes, 1000),
    createdAt: Number(x.createdAt) || Date.now(),
    updatedAt: Number(x.updatedAt) || Date.now()
  };
}
const validId = id => /^[A-Za-z0-9_-]{6,64}$/.test(id);

function view(rec, auth) {
  const p = JSON.parse(rec.d);
  p._o = rec.owner;
  p._on = rec.ownerName || '';
  const mine = auth.r === 'admin' || rec.owner === auth.m;
  p._mine = mine;
  if (!mine) { p.aadhaarLast4 = p.aadhaar ? p.aadhaar.slice(-4) : ''; p.aadhaar = ''; }
  return p;
}

/* ---------- handler ---------- */
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const send = (code, obj) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(obj)); };
  try {
    if (req.method !== 'POST') return send(405, { error: 'POST only' });
    if (!SECRET() || SECRET().length < 16 || !FAMILY_CODE() || !ADMIN_PASSWORD()) return send(500, { error: 'setup', message: 'സെർവർ സെറ്റപ്പ് പൂർത്തിയായിട്ടില്ല (environment variables).' });
    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
    body = body || {};
    const ip = String((req.headers && (req.headers['x-forwarded-for'] || '')) || (req.socket && req.socket.remoteAddress) || '').split(',')[0].trim();
    const act = body.action;

    if (act === 'login') {
      if (throttled(ip)) return send(429, { error: 'rate', message: 'കുറച്ച് കഴിഞ്ഞ് വീണ്ടും ശ്രമിക്കുക.' });
      if (body.role === 'admin') {
        if (!safeEq(body.password || '', ADMIN_PASSWORD())) { await sleep(500); return send(401, { error: 'bad', message: 'പാസ്‌വേഡ് ശരിയല്ല.' }); }
        return send(200, { token: sign({ r: 'admin', m: 'admin', n: 'Admin', e: Date.now() + 30 * DAY }), role: 'admin', name: 'Admin' });
      }
      if (!safeEq(body.code || '', FAMILY_CODE())) { await sleep(500); return send(401, { error: 'code', message: 'കുടുംബ കോഡ് ശരിയല്ല.' }); }
      const name = s(body.name, 60).trim().replace(/\s+/g, ' ');
      const pin = s(body.pin, 10);
      if (name.length < 2) return send(400, { error: 'name', message: 'പേര് നൽകുക.' });
      if (!/^\d{4,6}$/.test(pin)) return send(400, { error: 'pin', message: 'PIN 4 മുതൽ 6 വരെ അക്കങ്ങൾ ആയിരിക്കണം.' });
      const id = memberId(name);
      const m = await store.get('members', id);
      if (body.create) {
        if (m) return send(409, { error: 'exists', message: 'ഈ പേര് നേരത്തെ ഉണ്ട്. "ഇതിനകം ഉള്ളവർ" എന്നതിൽ PIN കൊടുത്ത് കയറുക, അല്ലെങ്കിൽ പേരിനൊപ്പം വീട്ടുപേരോ സ്ഥലമോ ചേർക്കുക.' });
        await store.commit([{ op: 'set', col: 'members', id, obj: { name, pin: hashPin(pin), fails: 0, lockUntil: 0, createdAt: Date.now() } }]);
      } else {
        if (!m) { await sleep(400); return send(401, { error: 'nouser', message: 'ഈ പേരിൽ ആരും ഇല്ല. "പുതിയ ആൾ" തിരഞ്ഞെടുക്കുക.' }); }
        if (m.lockUntil && m.lockUntil > Date.now()) return send(429, { error: 'locked', message: 'തെറ്റായ PIN പല തവണ കൊടുത്തു. 10 മിനിറ്റ് കഴിഞ്ഞ് ശ്രമിക്കുക.' });
        if (!checkPin(pin, m.pin)) {
          const fails = (m.fails || 0) + 1;
          await store.commit([{ op: 'set', col: 'members', id, obj: Object.assign({}, m, { fails: fails >= 5 ? 0 : fails, lockUntil: fails >= 5 ? Date.now() + 600000 : 0 }) }]);
          await sleep(400);
          return send(401, { error: 'pin', message: 'PIN ശരിയല്ല.' });
        }
        if (m.fails) await store.commit([{ op: 'set', col: 'members', id, obj: Object.assign({}, m, { fails: 0, lockUntil: 0 }) }]);
      }
      return send(200, { token: sign({ r: 'member', m: id, n: m ? m.name : name, e: Date.now() + 30 * DAY }), role: 'member', name: m ? m.name : name });
    }

    const auth = verify(body.token);
    if (!auth) return send(401, { error: 'auth', message: 'വീണ്ടും ലോഗിൻ ചെയ്യുക.' });

    if (act === 'list') {
      const rows = await store.list('people');
      return send(200, { role: auth.r, name: auth.n, people: rows.map(r => view(r, auth)) });
    }

    if (act === 'save') {
      const incoming = (Array.isArray(body.people) ? body.people : []).slice(0, 400);
      const existing = new Map((await store.list('people')).map(r => [r._id, r]));
      const writes = [], saved = [], skipped = [];
      incoming.forEach(x => {
        if (!x || !validId(s(x.id, 64))) { skipped.push(x && x.id); return; }
        const p = cleanPerson(x);
        if (!p.name) { skipped.push(p.id); return; }
        const cur = existing.get(p.id);
        let owner, ownerName;
        if (cur) {
          if (auth.r !== 'admin' && cur.owner !== auth.m) { skipped.push(p.id); return; }
          owner = cur.owner; ownerName = cur.ownerName;
        } else { owner = auth.m; ownerName = auth.n; }
        p.updatedAt = Date.now();
        writes.push({ op: 'set', col: 'people', id: p.id, obj: { owner, ownerName: ownerName || '', d: JSON.stringify(p), updatedAt: p.updatedAt } });
        saved.push(p.id);
      });
      await store.commit(writes);
      return send(200, { saved, skipped });
    }

    if (act === 'delete') {
      if (auth.r !== 'admin') return send(403, { error: 'forbidden', message: 'ഡിലീറ്റ് അഡ്മിന് മാത്രം.' });
      const ids = (Array.isArray(body.ids) ? body.ids : []).filter(validId);
      await store.commit(ids.map(id => ({ op: 'del', col: 'people', id })));
      return send(200, { deleted: ids.length });
    }

    if (act === 'members') {
      if (auth.r !== 'admin') return send(403, { error: 'forbidden' });
      const rows = await store.list('members');
      return send(200, { members: rows.map(r => ({ id: r._id, name: r.name })) });
    }
    if (act === 'removeMember') {
      if (auth.r !== 'admin') return send(403, { error: 'forbidden' });
      if (!/^[0-9a-f]{24}$/.test(s(body.id, 30))) return send(400, { error: 'bad' });
      await store.commit([{ op: 'del', col: 'members', id: body.id }]);
      return send(200, { ok: true });
    }
    if (act === 'resetPin') {
      if (auth.r !== 'admin') return send(403, { error: 'forbidden' });
      const id = s(body.id, 30), pin = s(body.pin, 10);
      if (!/^[0-9a-f]{24}$/.test(id) || !/^\d{4,6}$/.test(pin)) return send(400, { error: 'bad', message: 'PIN 4 മുതൽ 6 വരെ അക്കങ്ങൾ.' });
      const m = await store.get('members', id);
      if (!m) return send(404, { error: 'nouser' });
      await store.commit([{ op: 'set', col: 'members', id, obj: Object.assign({}, m, { pin: hashPin(pin), fails: 0, lockUntil: 0 }) }]);
      return send(200, { ok: true });
    }
    return send(400, { error: 'action' });
  } catch (e) {
    console.error(e);
    return send(500, { error: 'server', message: 'സെർവറിൽ തകരാറ്. കുറച്ച് കഴിഞ്ഞ് ശ്രമിക്കുക.' });
  }
};
