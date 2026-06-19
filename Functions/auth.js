const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const jwt     = require('jsonwebtoken');

const USERS_PATH  = path.join(__dirname, '../Sources/data/users.json');
const COOKIE_NAME = '5elg_session';
const JWT_EXPIRY  = '8h';

// Derive secret once at startup — env preferred, else random (survives restarts if env set)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// ── User store ────────────────────────────────────────────────────────────────

function loadUsers() {
    try {
        const raw = fs.readFileSync(USERS_PATH, 'utf8').trim();
        return raw ? JSON.parse(raw) : [];
    } catch (_) { return []; }
}

function saveUsers(users) {
    fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2), 'utf8');
}

// ── Password ──────────────────────────────────────────────────────────────────

function hashPassword(password, salt) {
    if (!salt) salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256').toString('hex');
    return { hash, salt };
}

function verifyPassword(password, storedHash, salt) {
    try {
        const { hash } = hashPassword(password, salt);
        return crypto.timingSafeEqual(
            Buffer.from(hash,       'hex'),
            Buffer.from(storedHash, 'hex')
        );
    } catch (_) { return false; }
}

// ── User lookup ───────────────────────────────────────────────────────────────

function findUser(username) {
    return loadUsers().find(u => u.username === username) || null;
}

function touchLastLogin(username) {
    const users = loadUsers();
    const u = users.find(u => u.username === username);
    if (u) { u.lastLogin = new Date().toISOString(); saveUsers(users); }
}

// ── JWT ───────────────────────────────────────────────────────────────────────

function generateToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY }
    );
}

function verifyToken(token) {
    try { return jwt.verify(token, JWT_SECRET); }
    catch (_) { return null; }
}

// ── Cookie parser (no extra dep) ──────────────────────────────────────────────

function parseCookies(req) {
    const out = {};
    const hdr = req.headers.cookie || '';
    hdr.split(';').forEach(part => {
        const [k, ...v] = part.split('=');
        if (k) out[k.trim()] = decodeURIComponent(v.join('='));
    });
    return out;
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

const _attempts = {}; // ip -> { count, blockedUntil }
const BLOCK_AFTER = 5;
const BLOCK_MS    = 15 * 60 * 1000; // 15 min

function checkRateLimit(ip) {
    const now = Date.now();
    const e = _attempts[ip];
    if (e && e.blockedUntil > now)
        return { blocked: true, remainingSec: Math.ceil((e.blockedUntil - now) / 1000) };
    return { blocked: false };
}

function recordFailedAttempt(ip) {
    if (!_attempts[ip]) _attempts[ip] = { count: 0, blockedUntil: 0 };
    _attempts[ip].count++;
    if (_attempts[ip].count >= BLOCK_AFTER) {
        _attempts[ip].blockedUntil = Date.now() + BLOCK_MS;
        _attempts[ip].count = 0;
    }
}

function clearFailedAttempts(ip) {
    delete _attempts[ip];
}

// ── Auth middleware ───────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
    const cookies = parseCookies(req);
    const token   = cookies[COOKIE_NAME]
                 || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');

    const payload = token ? verifyToken(token) : null;
    if (payload) {
        req.user = payload;
        return next();
    }

    // API calls → JSON 401; web pages → redirect to login
    const isApi = req.originalUrl.startsWith('/api') ||
                  (req.headers.accept || '').includes('application/json');
    if (isApi) return res.status(401).json({ error: 'Unauthorized' });

    const next_url = encodeURIComponent(req.originalUrl || '/web/index');
    return res.redirect(`/run/login?next=${next_url}`);
}

// ── User management ───────────────────────────────────────────────────────────

function createUser(username, password, role = 'viewer', extra = {}) {
    const users = loadUsers();
    if (users.find(u => u.username === username)) throw new Error('User already exists');
    const { hash, salt } = hashPassword(password);
    const user = {
        id:           crypto.randomBytes(8).toString('hex'),
        username,
        passwordHash: hash,
        salt,
        role,
        createdAt:    new Date().toISOString(),
        lastLogin:    null,
        displayName:  extra.displayName || username,
    };
    users.push(user);
    saveUsers(users);
    const { passwordHash: _, salt: __, ...safe } = user;
    return safe;
}

function updateUserPassword(username, newPassword) {
    const users = loadUsers();
    const idx = users.findIndex(u => u.username === username);
    if (idx === -1) throw new Error('User not found');
    const { hash, salt } = hashPassword(newPassword);
    users[idx].passwordHash = hash;
    users[idx].salt = salt;
    saveUsers(users);
}

function deleteUser(username) {
    const users = loadUsers();
    const next  = users.filter(u => u.username !== username);
    if (next.length === users.length) throw new Error('User not found');
    // Never delete the last admin
    const adminsLeft = next.filter(u => u.role === 'admin');
    if (adminsLeft.length === 0 && users.find(u => u.username === username)?.role === 'admin')
        throw new Error('Cannot delete the last admin account');
    saveUsers(next);
}

function listUsers() {
    return loadUsers().map(({ passwordHash, salt, ...safe }) => safe);
}

module.exports = {
    COOKIE_NAME, JWT_EXPIRY,
    loadUsers, listUsers, findUser, touchLastLogin,
    hashPassword, verifyPassword,
    generateToken, verifyToken,
    parseCookies,
    checkRateLimit, recordFailedAttempt, clearFailedAttempts,
    authMiddleware,
    createUser, updateUserPassword, deleteUser,
};
