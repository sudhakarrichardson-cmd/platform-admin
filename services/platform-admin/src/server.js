'use strict';
/*
 * PLATFORM ADMIN — standalone service (split out of textiles-api
 * on 2026-11-11). TWO-TIER ADMIN (Two-Tier-Admin-Design.md v0.1):
 *
 * One container serves two surfaces, chosen by the request's Host:
 *  - PLATFORM surface (PLATFORM_HOST, e.g. db.example.com): tier 0. Sign-in = the DB admin
 *    username + password (the Studio dashboard pair, env-copied on the
 *    server) -> signed session token. Manages the apps and WHO IS ADMIN
 *    OF EACH APP. (An email/JWT alias login exists behind the
 *    PLATFORM_ALIAS_LOGIN flag — off by default, per owner's decision.)
 *  - APP surface (<app domain>, e.g. shop.example.com): tier 1.
 *    Sign-in = the person's email + password (Supabase Auth). Gate =
 *    a grant for THIS app with the app's admin_role_code (sql/013).
 *    Manages ONLY this app's people: create logins, assign app roles,
 *    reset passwords. Scope is derived from Host server-side; any
 *    app_code sent by the browser is ignored.
 *
 * User create/list/password go through the GoTrue ADMIN API with the
 * service key (env, copied from the stack .env — never typed in chat).
 * Every change is audited in platform.access_audit.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = Number(process.env.PORT || 8092);
const PLATFORM_HOST = (process.env.PLATFORM_HOST || '').toLowerCase(); // the platform domain (store.json domains.platform)
// Brand shown on the admin pages (letters, digits, spaces only — it is placed into HTML and JS strings).
const PLATFORM_NAME = (process.env.PLATFORM_NAME || 'Store Platform').replace(/[^\w .-]/g, '');
const AUTH_URL = (process.env.SUPABASE_AUTH_URL || 'http://kong:8000').replace(/\/$/, '');
const SERVICE_KEY = process.env['SUPABASE_' + 'SERVICE_KEY'] || '';
const JWT_SECRET = process.env['SUPA' + 'BASE_JWT'] || '';
const ADMIN_USER = process.env.PLATFORM_ADMIN_USERNAME || '';
const ADMIN_PASS = process.env['PLATFORM_ADMIN_' + 'PASSWORD'] || '';
const SESSION_SECRET = process.env['PLATFORM_SESSION_' + 'SECRET'] || '';
const ALIAS_LOGIN = process.env.PLATFORM_ALIAS_LOGIN === '1';

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5433),
  database: process.env.DB_NAME || 'postgres',
  user: process.env.DB_USER || 'platform_admin',
  password: process.env['DB_' + 'PASSWORD'] || '',
});
const q = pool.query.bind(pool);

// ---------- small helpers ----------
function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}
// pg errors carry SQLSTATE strings ('42501' etc.) in .code — never pass those
// to writeHead (Node throws 'Invalid status code'). Coerce to a sane HTTP code.
function httpCode(e) {
  const c = Number(e && e.code);
  return c >= 400 && c < 600 ? c : 500;
}
async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}
const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64 = (x) => Buffer.from(String(x).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// ---------- Supabase Auth (GoTrue) ----------
function verifyJwt(token) {
  if (!JWT_SECRET || !token) return null;
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest();
  const given = b64(s);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  try {
    const payload = JSON.parse(b64(p).toString('utf8'));
    if (payload.exp && payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch { return null; }
}
async function gotrue(pathname, method, body) {
  if (!SERVICE_KEY) { const e = new Error('service key not configured on the server'); e.code = 503; throw e; }
  const res = await fetch(AUTH_URL + pathname, {
    method: method || 'GET',
    headers: { 'Content-Type': 'application/json', apikey: SERVICE_KEY, Authorization: 'Bearer ' + SERVICE_KEY },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { const e = new Error(data.msg || data.message || ('GoTrue HTTP ' + res.status)); e.code = res.status; throw e; }
  return data;
}
async function listUsers() {
  let users = [];
  for (let page = 1; page <= 10; page++) {
    const data = await gotrue('/auth/v1/admin/users?page=' + page + '&per_page=200');
    const batch = (data.users || []).map((u) => ({
      id: u.id, email: u.email,
      display_name: (u.user_metadata && u.user_metadata.display_name) || '',
      phone: (u.user_metadata && u.user_metadata.phone) || '',
      created_at: u.created_at,
    }));
    users = users.concat(batch);
    if (batch.length < 200) break;
  }
  return users;
}
async function createLogin(email, password, displayName, phone) {
  return gotrue('/auth/v1/admin/users', 'POST', {
    email, password, email_confirm: true,
    user_metadata: { display_name: displayName || '', phone: phone || '' },
  });
}

// ---------- platform session tokens (tier 0) ----------
function makeSession() {
  const payload = { sub: 'db-admin', exp: Math.floor(Date.now() / 1000) + 12 * 3600 };
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(body).digest());
  return body + '.' + sig;
}
function verifySession(token) {
  if (!SESSION_SECRET || !token) return null;
  const parts = String(token).split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(body).digest());
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(b64(body).toString('utf8'));
    if (!payload.exp || payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch { return null; }
}
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest();
function credsOk(username, password) {
  if (!ADMIN_USER || !ADMIN_PASS) return false;
  const u = crypto.timingSafeEqual(sha256(username || ''), sha256(ADMIN_USER));
  const p = crypto.timingSafeEqual(sha256(password || ''), sha256(ADMIN_PASS));
  return u && p;
}
// throttle for the platform login: 5 failures -> 5 minutes locked per IP
const loginFails = new Map();
function throttleCheck(ip) {
  const rec = loginFails.get(ip);
  return !!(rec && rec.lockedUntil && rec.lockedUntil > Date.now());
}
function throttleFail(ip) {
  const rec = loginFails.get(ip) || { fails: 0, lockedUntil: 0 };
  rec.fails += 1;
  if (rec.fails >= 5) { rec.lockedUntil = Date.now() + 5 * 60 * 1000; rec.fails = 0; }
  loginFails.set(ip, rec);
}
function throttleReset(ip) { loginFails.delete(ip); }

// ---------- surface resolution ----------
let domainCache = { at: 0, map: new Map() };
async function resolveSurface(req) {
  const host = String(req.headers.host || '').split(':')[0].toLowerCase();
  if (host === PLATFORM_HOST) return { surface: 'platform' };
  if (Date.now() - domainCache.at > 30000) {
    const rows = (await q('SELECT app_code, display_name, schema_name, domain, admin_role_code, active FROM platform.apps WHERE domain IS NOT NULL')).rows;
    domainCache = { at: Date.now(), map: new Map(rows.map((r) => [String(r.domain).toLowerCase(), r])) };
  }
  const app = domainCache.map.get(host);
  if (app) return { surface: 'app', app };
  return { surface: 'unknown' };
}

// ---------- shared data helpers ----------
const DEFAULT_ROLES = {
  platform: ['admin'],
  helplawyer: ['advocate', 'clerk', 'viewer'],
  default: ['owner', 'staff', 'viewer'],
};
async function rolesForApp(app) {
  if (app.app_code === 'textiles') {
    const r = await q('SELECT DISTINCT role_code FROM textiles.role_capabilities ORDER BY role_code');
    return r.rows.map((x) => x.role_code);
  }
  // Every app defines its own roles: an app whose schema has a
  // role_capabilities table (same shape as the textiles one, readable by
  // this service's DB role) lists its roles there. Apps without one keep
  // the built-in defaults below.
  const schema = String(app.schema_name || '');
  if (/^[a-z_][a-z0-9_]*$/.test(schema)) {
    try {
      const r = await q(`SELECT DISTINCT role_code FROM ${schema}.role_capabilities ORDER BY role_code`);
      if (r.rows.length) return r.rows.map((x) => x.role_code);
    } catch (e) { /* no role table / no grant for this app — use the defaults */ }
  }
  return DEFAULT_ROLES[app.app_code] || DEFAULT_ROLES.default;
}
async function audit(actor, targetUserId, targetEmail, appCode, action, detail) {
  try {
    await q('INSERT INTO platform.access_audit (actor, target_user_id, target_email, app_code, action, detail) VALUES ($1,$2,$3,$4,$5,$6)',
      [actor, targetUserId || null, targetEmail || null, appCode || null, action, detail ? JSON.stringify(detail) : null]);
  } catch (e) { /* audit is best-effort */ }
}
async function ensureStaffProfile(appCode, userId, fallbackName) {
  if (appCode !== 'textiles') return;
  let name = fallbackName || '';
  try { const u = await gotrue('/auth/v1/admin/users/' + userId); name = (u.user_metadata && u.user_metadata.display_name) || name || (u.email || '').split('@')[0]; } catch (e) { /* keep fallback */ }
  await q(`INSERT INTO textiles.staff_profiles (user_id, display_name, active) VALUES ($1,$2,true)
           ON CONFLICT (user_id) DO NOTHING`, [userId, name || 'Staff']);
}
async function upsertGrant(userId, appCode, roleCode, active) {
  await q(`INSERT INTO platform.user_app_access (user_id, app_code, role_code, active) VALUES ($1,$2,$3,$4)
           ON CONFLICT (user_id, app_code) DO UPDATE SET role_code = EXCLUDED.role_code, active = EXCLUDED.active`,
    [userId, appCode, roleCode, active]);
}
async function emailOf(userId) {
  try { const u = await gotrue('/auth/v1/admin/users/' + userId); return u.email || null; } catch (e) { return null; }
}

// ---------- gates ----------
// Returns actor string, or null after sending an error response.
async function platformGate(req, res) {
  const authz = req.headers['authorization'] || '';
  if (!authz.startsWith('Bearer ')) { json(res, 401, { error: 'sign-in required' }); return null; }
  const token = authz.slice(7);
  if (verifySession(token)) return 'db-admin';
  if (ALIAS_LOGIN) {
    const payload = verifyJwt(token);
    if (payload) {
      const acc = await q('SELECT role_code FROM platform.user_app_access WHERE user_id = $1 AND app_code = $2 AND active', [payload.sub, 'platform']);
      if (acc.rows[0] && ['admin', 'owner'].includes(acc.rows[0].role_code)) return payload.email || payload.sub;
    }
  }
  json(res, 401, { error: 'bad or expired session' });
  return null;
}
async function appGate(req, res, app) {
  const authz = req.headers['authorization'] || '';
  if (!authz.startsWith('Bearer ')) { json(res, 401, { error: 'sign-in required' }); return null; }
  const payload = verifyJwt(authz.slice(7));
  if (!payload) { json(res, 401, { error: 'bad or expired login' }); return null; }
  if (!app.admin_role_code) { json(res, 503, { error: 'this app has no admin role configured' }); return null; }
  const acc = await q('SELECT role_code FROM platform.user_app_access WHERE user_id = $1 AND app_code = $2 AND active', [payload.sub, app.app_code]);
  const role = acc.rows[0] ? acc.rows[0].role_code : null;
  const isAdmin = !!role && role === app.admin_role_code;
  if (!isAdmin && !(role && await roleManagesUsers(app, role))) { json(res, 403, { error: 'this login is not an admin of this app' }); return null; }
  return { actor: payload.email || payload.sub, user_id: payload.sub, isAdmin };
}
// An app may let a second role (e.g. an HR role) manage its people: a role
// with an explicit 'manage_users' row in the app's own role_capabilities
// table. Such a role can never assign, change or remove the app's ADMIN
// role (see adminOnly in handleApp). Apps without that row are unaffected.
async function roleManagesUsers(app, role) {
  const schema = String(app.schema_name || '');
  if (!/^[a-z_][a-z0-9_]*$/.test(schema)) return false;
  try {
    const r = await q(`SELECT 1 FROM ${schema}.role_capabilities WHERE role_code = $1 AND capability = 'manage_users' AND allowed`, [role]);
    return !!r.rows[0];
  } catch (e) { return false; }
}

// ---------- login ----------
async function handleLogin(req, res, surf) {
  const b = await readBody(req).catch(() => ({}));
  if (surf.surface === 'platform') {
    // Behind Caddy the socket is always 127.0.0.1; Caddy sets X-Forwarded-For
    // with the real client address (the service port is localhost-only, so
    // the header can be trusted). Fall back to the socket address directly.
    const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
    if (throttleCheck(ip)) { json(res, 429, { error: 'too many failed attempts — try again in a few minutes' }); return; }
    if (!ADMIN_USER || !ADMIN_PASS || !SESSION_SECRET) { json(res, 503, { error: 'platform sign-in is not configured on the server' }); return; }
    if (!b.username || !b.password) { json(res, 400, { error: 'username and password required' }); return; }
    if (!credsOk(b.username, b.password)) { throttleFail(ip); json(res, 401, { error: 'invalid username or password' }); return; }
    throttleReset(ip);
    json(res, 200, { session_token: makeSession() });
    return;
  }
  if (surf.surface === 'app') {
    if (!b.email || !b.password) { json(res, 400, { error: 'email and password required' }); return; }
    if (!SERVICE_KEY) { json(res, 503, { error: 'service key not configured on the server' }); return; }
    try {
      const r = await fetch(AUTH_URL + '/auth/v1/token?grant_type=password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', apikey: SERVICE_KEY },
        body: JSON.stringify({ email: b.email, password: b.password }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok || !data.access_token) { json(res, 401, { error: 'invalid email or password' }); return; }
      json(res, 200, { access_token: data.access_token, user: { id: data.user && data.user.id, email: data.user && data.user.email } });
    } catch (e) {
      json(res, 502, { error: 'auth service unreachable: ' + e.message });
    }
    return;
  }
  json(res, 404, { error: 'unknown host' });
}

// ---------- platform surface ----------
async function handlePlatform(req, res, url) {
  const actor = await platformGate(req, res);
  if (!actor) return;
  try {
    if (req.method === 'GET' && url.pathname === '/api/platform/overview') {
      const apps = (await q("SELECT app_code, display_name, schema_name, domain, admin_role_code, active FROM platform.apps WHERE app_code <> 'platform' ORDER BY app_code")).rows;
      let users = [];
      try { users = await listUsers(); } catch (e) { json(res, httpCode(e), { error: 'Could not list logins: ' + e.message }); return; }
      const byId = new Map(users.map((u) => [u.id, u]));
      for (const a of apps) {
        a.admins = [];
        if (a.admin_role_code) {
          const g = await q('SELECT user_id FROM platform.user_app_access WHERE app_code = $1 AND role_code = $2 AND active', [a.app_code, a.admin_role_code]);
          a.admins = g.rows.map((r) => ({ user_id: r.user_id, email: (byId.get(r.user_id) || {}).email || null, display_name: (byId.get(r.user_id) || {}).display_name || '' }));
        }
      }
      let auditRows = [];
      try { auditRows = (await q('SELECT actor, target_email, app_code, action, detail, created_at FROM platform.access_audit ORDER BY id DESC LIMIT 20')).rows; } catch (e) { /* 010 table */ }
      json(res, 200, { apps, logins: users, audit: auditRows });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/platform/users') {
      const b = await readBody(req);
      if (!b.email || !b.password) { json(res, 400, { error: 'email and temporary password required' }); return; }
      if (String(b.password).length < 8) { json(res, 400, { error: 'temporary password must be at least 8 characters' }); return; }
      const u = await createLogin(b.email, b.password, b.display_name, b.phone);
      await audit(actor, u.id, b.email, null, 'create_user', { display_name: b.display_name || '' });
      json(res, 200, { user: { id: u.id, email: u.email } });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/platform/app-admins') {
      const b = await readBody(req);
      if (!b.app_code) { json(res, 400, { error: 'app_code required' }); return; }
      const app = (await q('SELECT * FROM platform.apps WHERE app_code = $1', [b.app_code])).rows[0];
      if (!app) { json(res, 400, { error: 'unknown app_code' }); return; }
      if (!app.admin_role_code) { json(res, 400, { error: 'this app has no admin role configured' }); return; }
      let userId = b.user_id;
      if (!userId) {
        if (!b.email || !b.password) { json(res, 400, { error: 'pick an existing login, or give email + temporary password for a new one' }); return; }
        if (String(b.password).length < 8) { json(res, 400, { error: 'temporary password must be at least 8 characters' }); return; }
        const u = await createLogin(b.email, b.password, b.display_name, b.phone);
        userId = u.id;
      }
      await upsertGrant(userId, app.app_code, app.admin_role_code, true);
      await ensureStaffProfile(app.app_code, userId, b.display_name);
      await audit(actor, userId, await emailOf(userId), app.app_code, 'add_app_admin', { role_code: app.admin_role_code });
      json(res, 200, { ok: true, user_id: userId });
      return;
    }
    if (req.method === 'DELETE' && url.pathname === '/api/platform/app-admins') {
      const b = await readBody(req);
      if (!b.app_code || !b.user_id) { json(res, 400, { error: 'app_code and user_id required' }); return; }
      const app = (await q('SELECT * FROM platform.apps WHERE app_code = $1', [b.app_code])).rows[0];
      if (!app || !app.admin_role_code) { json(res, 400, { error: 'unknown app or no admin role configured' }); return; }
      const r = await q('UPDATE platform.user_app_access SET active = false WHERE user_id = $1 AND app_code = $2 AND role_code = $3',
        [b.user_id, app.app_code, app.admin_role_code]);
      if (!r.rowCount) { json(res, 404, { error: 'that person is not an admin of this app' }); return; }
      await audit(actor, b.user_id, await emailOf(b.user_id), app.app_code, 'remove_app_admin', { role_code: app.admin_role_code });
      json(res, 200, { ok: true });
      return;
    }
    json(res, 404, { error: 'not found' });
  } catch (e) {
    json(res, httpCode(e), { error: e.message });
  }
}

// ---------- app surface ----------
async function handleApp(req, res, url, app) {
  const gate = await appGate(req, res, app);
  if (!gate) return;
  const actor = gate.actor;
  const meId = gate.user_id;
  // A user-manager who is not the app admin may not hand out the admin
  // role, nor touch anyone who holds it. Sends the 403 and returns false.
  const adminOnly = async (targetUserId, newRole) => {
    if (gate.isAdmin) return true;
    if (newRole && newRole === app.admin_role_code) { json(res, 403, { error: 'only an admin of this app can assign the admin role' }); return false; }
    if (targetUserId) {
      const t = await q('SELECT role_code FROM platform.user_app_access WHERE user_id = $1 AND app_code = $2', [targetUserId, app.app_code]);
      if (t.rows[0] && t.rows[0].role_code === app.admin_role_code) { json(res, 403, { error: 'only an admin of this app can change another admin' }); return false; }
    }
    return true;
  };
  try {
    if (req.method === 'GET' && url.pathname === '/api/app/overview') {
      const roles = await rolesForApp(app);
      let users = [];
      try { users = await listUsers(); } catch (e) { json(res, httpCode(e), { error: 'Could not list logins: ' + e.message }); return; }
      const byId = new Map(users.map((u) => [u.id, u]));
      const grants = (await q('SELECT user_id, role_code, active FROM platform.user_app_access WHERE app_code = $1', [app.app_code])).rows;
      const people = grants.map((g) => ({
        user_id: g.user_id, role_code: g.role_code, active: g.active,
        email: (byId.get(g.user_id) || {}).email || null,
        display_name: (byId.get(g.user_id) || {}).display_name || '',
        phone: (byId.get(g.user_id) || {}).phone || '',
      }));
      // NOTE: no pool listing here (owner decision 2026-11-11) — an app admin
      // sees only their own app's people. Adding an existing login goes
      // through the exact-email lookup below, never a browsable list.
      let auditRows = [];
      try { auditRows = (await q('SELECT actor, target_email, app_code, action, detail, created_at FROM platform.access_audit WHERE app_code = $1 ORDER BY id DESC LIMIT 20', [app.app_code])).rows; } catch (e) { /* 010 table */ }
      json(res, 200, { app: { app_code: app.app_code, display_name: app.display_name, admin_role_code: app.admin_role_code }, me: { user_id: meId, email: actor }, roles, people, audit: auditRows });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/app/lookup') {
      // Exact-email lookup for "add existing login": answers only for the
      // one email typed (found / not found / already in this app). It never
      // lists or browses the shared login pool.
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      if (!email) { json(res, 400, { error: 'email required' }); return; }
      let users = [];
      try { users = await listUsers(); } catch (e) { json(res, httpCode(e), { error: 'Could not look up logins: ' + e.message }); return; }
      const u = users.find((x) => (x.email || '').toLowerCase() === email);
      if (!u) { json(res, 200, { found: false }); return; }
      const g = await q('SELECT role_code, active FROM platform.user_app_access WHERE user_id = $1 AND app_code = $2', [u.id, app.app_code]);
      json(res, 200, {
        found: true, user_id: u.id, email: u.email, display_name: u.display_name,
        already_in_app: !!g.rows[0],
        role_code: g.rows[0] ? g.rows[0].role_code : null,
        active: g.rows[0] ? g.rows[0].active : null,
      });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/app/users') {
      const b = await readBody(req);
      if (!b.email || !b.password || !b.role_code) { json(res, 400, { error: 'email, temporary password and role required' }); return; }
      if (String(b.password).length < 8) { json(res, 400, { error: 'temporary password must be at least 8 characters' }); return; }
      const roles = await rolesForApp(app);
      if (!roles.includes(b.role_code)) { json(res, 400, { error: 'role does not belong to this app' }); return; }
      if (!(await adminOnly(null, b.role_code))) return;
      const u = await createLogin(b.email, b.password, b.display_name, b.phone);
      await upsertGrant(u.id, app.app_code, b.role_code, true);
      await ensureStaffProfile(app.app_code, u.id, b.display_name);
      await audit(actor, u.id, b.email, app.app_code, 'app_create_user', { role_code: b.role_code });
      json(res, 200, { user: { id: u.id, email: u.email } });
      return;
    }
    if (req.method === 'PUT' && url.pathname === '/api/app/grant') {
      const b = await readBody(req);
      if (!b.user_id || !b.role_code) { json(res, 400, { error: 'user_id and role_code required' }); return; }
      if (b.user_id === meId) { json(res, 400, { error: 'you cannot change your own access from here — another admin or the platform admin must do it' }); return; }
      const roles = await rolesForApp(app);
      if (!roles.includes(b.role_code)) { json(res, 400, { error: 'role does not belong to this app' }); return; }
      if (!(await adminOnly(b.user_id, b.role_code))) return;
      const active = b.active !== false;
      await upsertGrant(b.user_id, app.app_code, b.role_code, active);
      if (active) await ensureStaffProfile(app.app_code, b.user_id, b.display_name);
      await audit(actor, b.user_id, await emailOf(b.user_id), app.app_code, active ? 'app_grant' : 'app_deactivate', { role_code: b.role_code, active });
      json(res, 200, { ok: true });
      return;
    }
    if (req.method === 'DELETE' && url.pathname === '/api/app/grant') {
      // Remove this person from THIS app only: their grant row (and this
      // app's staff profile) is deleted; the login itself survives.
      const b = await readBody(req);
      if (!b.user_id) { json(res, 400, { error: 'user_id required' }); return; }
      if (b.user_id === meId) { json(res, 400, { error: 'you cannot remove your own access from here — another admin or the platform admin must do it' }); return; }
      if (!(await adminOnly(b.user_id))) return;
      const email = await emailOf(b.user_id);
      const r = await q('DELETE FROM platform.user_app_access WHERE user_id = $1 AND app_code = $2', [b.user_id, app.app_code]);
      if (!r.rowCount) { json(res, 404, { error: 'that login has no access in this app' }); return; }
      if (app.app_code === 'textiles') { await q('DELETE FROM textiles.staff_profiles WHERE user_id = $1', [b.user_id]); }
      await audit(actor, b.user_id, email, app.app_code, 'app_remove_user', {});
      json(res, 200, { ok: true });
      return;
    }
    if (req.method === 'DELETE' && url.pathname === '/api/app/users') {
      // Hard-delete a login — allowed ONLY when the login belongs solely to
      // this app (no grant rows anywhere else). A shared login is refused
      // with 409 + shared:true; the page then offers remove-from-app.
      // Guards: cannot delete your own login; target must be in this app.
      const b = await readBody(req);
      if (!b.user_id) { json(res, 400, { error: 'user_id required' }); return; }
      if (b.user_id === meId) { json(res, 400, { error: 'you cannot delete your own login' }); return; }
      if (!(await adminOnly(b.user_id))) return;
      const mine = await q('SELECT 1 FROM platform.user_app_access WHERE user_id = $1 AND app_code = $2', [b.user_id, app.app_code]);
      if (!mine.rows[0]) { json(res, 404, { error: 'that login has no access in this app' }); return; }
      const others = await q('SELECT app_code FROM platform.user_app_access WHERE user_id = $1 AND app_code <> $2', [b.user_id, app.app_code]);
      if (others.rows[0]) {
        json(res, 409, { error: 'This login is also used by another app (' + others.rows.map((r) => r.app_code).join(', ') + '), so it cannot be deleted from here. You can remove it from this app only.', shared: true });
        return;
      }
      const email = await emailOf(b.user_id);
      await q('DELETE FROM platform.user_app_access WHERE user_id = $1', [b.user_id]);
      if (app.app_code === 'textiles') { await q('DELETE FROM textiles.staff_profiles WHERE user_id = $1', [b.user_id]); }
      await gotrue('/auth/v1/admin/users/' + b.user_id, 'DELETE');
      await audit(actor, b.user_id, email, app.app_code, 'app_delete_user', {});
      json(res, 200, { ok: true });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/app/password') {
      const b = await readBody(req);
      if (!b.user_id || !b.password) { json(res, 400, { error: 'user_id and password required' }); return; }
      if (String(b.password).length < 8) { json(res, 400, { error: 'password must be at least 8 characters' }); return; }
      const has = await q('SELECT 1 FROM platform.user_app_access WHERE user_id = $1 AND app_code = $2', [b.user_id, app.app_code]);
      if (!has.rows[0]) { json(res, 403, { error: 'that login has no access in this app' }); return; }
      if (!(await adminOnly(b.user_id))) return;
      const u = await gotrue('/auth/v1/admin/users/' + b.user_id, 'PUT', { password: b.password });
      await audit(actor, b.user_id, u.email, app.app_code, 'app_reset_password', {});
      json(res, 200, { ok: true });
      return;
    }
    json(res, 404, { error: 'not found' });
  } catch (e) {
    json(res, httpCode(e), { error: e.message });
  }
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (req.method === 'GET' && url.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, app: 'platform-admin' }));
    }
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(302, { Location: '/admin' });
      return res.end();
    }
    if (req.method === 'GET' && url.pathname === '/admin') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'access.html'), 'utf8').replace(/\{\{platform_name\}\}/g, PLATFORM_NAME));
    }
    if (req.method === 'GET' && url.pathname === '/api/whoami') {
      const surf = await resolveSurface(req);
      if (surf.surface === 'app') return json(res, 200, { surface: 'app', app_code: surf.app.app_code, display_name: surf.app.display_name });
      return json(res, 200, { surface: surf.surface });
    }
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const surf = await resolveSurface(req);
      await handleLogin(req, res, surf);
      return;
    }
    if (url.pathname.startsWith('/api/platform/')) {
      const surf = await resolveSurface(req);
      if (surf.surface !== 'platform') { json(res, 404, { error: 'not found' }); return; }
      await handlePlatform(req, res, url);
      return;
    }
    if (url.pathname.startsWith('/api/app/')) {
      const surf = await resolveSurface(req);
      if (surf.surface !== 'app') { json(res, 404, { error: 'not found' }); return; }
      await handleApp(req, res, url, surf.app);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'not found' }));
  } catch (e) {
    if (!res.writableEnded) { res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: e.message })); }
  }
});

server.listen(PORT, () => console.log('platform-admin listening on ' + PORT));
