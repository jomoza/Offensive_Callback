const express = require('express');
const router  = express.Router();
const fs      = require('fs');
const path    = require('path');

const {
    COOKIE_NAME,
    findUser, verifyPassword, generateToken, touchLastLogin,
    checkRateLimit, recordFailedAttempt, clearFailedAttempts,
    parseCookies, verifyToken,
} = require('../Functions/auth');

const COOKIE_OPTS = {
    httpOnly: true,
    sameSite: 'Lax',
    maxAge:   8 * 60 * 60 * 1000, // 8 h
};

// ── GET /run/login ─────────────────────────────────────────────────────────────
router.get('/login', (req, res) => {
    // Already logged in → go home
    const cookies = parseCookies(req);
    if (cookies[COOKIE_NAME] && verifyToken(cookies[COOKIE_NAME])) {
        return res.redirect('/web/index');
    }
    const filePath = path.join(__dirname, '../Web/login.html');
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(500).send('Login page not found');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store');
        res.send(data);
    });
});

// ── POST /run/login ────────────────────────────────────────────────────────────
router.post('/login', (req, res) => {
    const clientIp = req.ip || req.connection?.remoteAddress || '0.0.0.0';
    const { blocked, remainingSec } = checkRateLimit(clientIp);

    if (blocked) {
        return res.status(429).json({
            error: `Too many failed attempts. Try again in ${remainingSec}s.`,
        });
    }

    const { username, password } = req.body || {};
    if (!username || !password)
        return res.status(400).json({ error: 'Username and password required' });

    const user = findUser(username);
    const valid = user && verifyPassword(password, user.passwordHash, user.salt);

    if (!valid) {
        recordFailedAttempt(clientIp);
        console.warn(`[AUTH] Failed login for "${username}" from ${clientIp}`);
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    clearFailedAttempts(clientIp);
    touchLastLogin(username);

    const token = generateToken(user);
    res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
    console.log(`[AUTH] Login OK: ${username} from ${clientIp}`);

    const next = req.body.next || req.query.next || '/web/index';
    // Sanitise redirect — only allow relative paths on this host
    const safe = next.startsWith('/') ? next : '/web/index';
    return res.json({ ok: true, redirect: safe });
});

// ── GET /run/logout ────────────────────────────────────────────────────────────
router.get('/logout', (req, res) => {
    res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'Lax' });
    console.log(`[AUTH] Logout from ${req.ip}`);
    return res.redirect('/run/login');
});

// ── GET /run/whoami ────────────────────────────────────────────────────────────
router.get('/whoami', (req, res) => {
    const cookies = parseCookies(req);
    const token   = cookies[COOKIE_NAME] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const payload = token ? verifyToken(token) : null;
    if (!payload) return res.status(401).json({ error: 'Not authenticated' });
    return res.json({ username: payload.username, role: payload.role });
});

// ── Public dealer pages ────────────────────────────────────────────────────────
const webfuncs = {
    runDealer: (req, res) => {
        const filePath = path.join(__dirname, '../Web/merca.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) { console.error('[!] Error reading merca.html:', err.message); return res.status(500).send('ERROR'); }
            res.status(200).send(data);
        });
    },
    runOldDealer: (req, res) => {
        const filePath = path.join(__dirname, '../Web/oldmerca.html');
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) { console.error('[!] Error reading oldmerca.html:', err.message); return res.status(500).send('ERROR'); }
            res.status(200).send(data);
        });
    },
};

router.use('/deal',         webfuncs.runDealer);
router.use('/try/exemple',  webfuncs.runOldDealer);

module.exports = router;
