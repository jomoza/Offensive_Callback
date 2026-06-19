const whois = require('whois-json');
const axios = require('axios');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const { IPINT } = require('../db');

const BLACKLIST_PATH = path.join(__dirname, '../../Sources/data/blacklist.json');

// ANSI escape codes
const C = {
    Reset:   "\x1b[0m",
    Bold:    "\x1b[1m",
    Dim:     "\x1b[2m",
    Red:     "\x1b[31m",
    Green:   "\x1b[32m",
    Yellow:  "\x1b[33m",
    Cyan:    "\x1b[36m",
    Magenta: "\x1b[35m",
    White:   "\x1b[37m",
};

/* ── Validate IP (v4 or v6) to prevent command injection ── */
function isValidIP(ip) {
    if (!ip || typeof ip !== 'string') return false;
    // IPv4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        return ip.split('.').every(n => parseInt(n, 10) <= 255);
    }
    // IPv6
    return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':');
}

function readBlacklist() {
    try {
        const raw = fs.readFileSync(BLACKLIST_PATH, 'utf8').trim();
        return raw ? JSON.parse(raw) : [];
    } catch (_) { return []; }
}

function writeBlacklist(list) {
    fs.writeFileSync(BLACKLIST_PATH, JSON.stringify(list, null, 2));
}

function runIptables(args) {
    return new Promise((resolve, reject) => {
        exec(`iptables ${args}`, (err, stdout, stderr) => {
            if (err) return reject(new Error(stderr || err.message));
            resolve(stdout);
        });
    });
}

/* ── banIP: add iptables DROP rule + persist to blacklist.json ── */
async function banIP(ip) {
    if (!isValidIP(ip)) throw new Error('Invalid IP address');

    // iptables: insert at top of INPUT so it takes effect immediately
    await runIptables(`-I INPUT -s ${ip} -j DROP`);
    // Also block outgoing responses (optional but thorough)
    await runIptables(`-I OUTPUT -d ${ip} -j DROP`).catch(() => {});

    const list = readBlacklist();
    if (!list.find(e => e.ip === ip)) {
        list.push({ ip, bannedAt: new Date().toISOString() });
        writeBlacklist(list);
    }
    console.log(`${C.Red}[5ELG-BAN]${C.Reset} Banned IP: ${C.Bold}${ip}${C.Reset}`);
    return { ip, banned: true };
}

/* ── unbanIP: remove iptables DROP rule + remove from blacklist.json ── */
async function unbanIP(ip) {
    if (!isValidIP(ip)) throw new Error('Invalid IP address');

    // Remove from iptables (ignore errors if rule doesn't exist)
    await runIptables(`-D INPUT -s ${ip} -j DROP`).catch(() => {});
    await runIptables(`-D OUTPUT -d ${ip} -j DROP`).catch(() => {});

    const list = readBlacklist();
    const filtered = list.filter(e => e.ip !== ip);
    writeBlacklist(filtered);
    console.log(`${C.Green}[5ELG-BAN]${C.Reset} Unbanned IP: ${C.Bold}${ip}${C.Reset}`);
    return { ip, banned: false };
}

/* ── getBlacklist: return current banned IPs ── */
function getBlacklist() {
    return readBlacklist();
}

/* ── safeParse: unwrap nested JSON strings safely ── */
function safeParse(raw) {
    if (!raw) return {};
    let parsed = raw;
    while (typeof parsed === 'string') {
        try { parsed = JSON.parse(parsed); }
        catch (e) { break; }
    }
    return (typeof parsed === 'object' && parsed !== null) ? parsed : {};
}

/* ══════════════════════════════════════════════════════
   GEO — ip-api.com (HTTP, free, no key, server-side)
══════════════════════════════════════════════════════ */
async function fetchGeoLocation(ip, retries = 3) {
    try {
        const response = await axios.get(
            `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query`,
            { timeout: 8000 }
        );
        const d = response.data;

        if (d.status !== 'success') {
            // ip-api returns { status: 'fail', message: 'reserved range' } for private IPs etc.
            console.warn(`${C.Yellow}[5ELG-GEO] ip-api status="${d.status}" for ${ip}: ${d.message || ''}${C.Reset}`);
            return null;
        }

        console.log(`${C.Cyan}[5ELG-GEO]${C.Reset} Geo ${C.Bold}${ip}${C.Reset}: ${d.city}, ${d.countryCode}`);
        return {
            country:     d.country     || '',
            countryCode: d.countryCode || '',
            regionName:  d.regionName  || '',
            city:        d.city        || '',
            lat:         d.lat         ?? null,
            lon:         d.lon         ?? null,
            isp:         d.isp         || '',
            org:         d.org         || '',
            as:          d.as          || '',
            query:       d.query       || ip,
        };
    } catch (error) {
        if (retries > 0) {
            console.warn(`${C.Yellow}[5ELG-GEO] Error fetching geo for ${ip} (${retries} retries left): ${error.message}${C.Reset}`);
            await new Promise(r => setTimeout(r, 3000));
            return fetchGeoLocation(ip, retries - 1);
        }
        console.error(`${C.Red}[5ELG-GEO] All retries failed for ${ip}: ${error.message}${C.Reset}`);
        return null;
    }
}

async function geolocateAndUpdate(ip) {
    try {
        const geoData = await fetchGeoLocation(ip);
        if (!geoData) return null;

        const [ipRecord] = await IPINT.findOrCreate({
            where:    { IP: ip },
            defaults: { MAC: null, DATA: null, GEO: null, SCAN: false, INTEL: null },
        });

        const normalized = {
            countryCode: geoData.countryCode || geoData.country_code || geoData.country || '',
            country:     geoData.country     || geoData.countryCode  || '',
            regionName:  geoData.regionName  || geoData.region       || '',
            city:        geoData.city        || '',
            lat:         geoData.lat         ?? null,
            lon:         geoData.lon         ?? null,
            isp:         geoData.isp         || geoData.org          || '',
            org:         geoData.org         || geoData.isp          || '',
            as:          geoData.as          || '',
            query:       geoData.query       || ip,
        };

        await ipRecord.update({ GEO: normalized });
        console.log(`${C.Green}[5ELG-GEO]${C.Reset} Saved: ${C.Bold}${ip}${C.Reset} → ${normalized.countryCode} ${normalized.city}`);
        return normalized;
    } catch (err) {
        console.error(`${C.Red}[5ELG-GEO] geolocateAndUpdate error for ${ip}: ${err.message}${C.Reset}`);
        return null; // don't rethrow — callers should not crash on geo failure
    }
}

/* ══════════════════════════════════════════════════════
   WHOIS
   Bugs fixed:
   - Removed `throw error` inside catch (was re-throwing and making
     saveGeoForIP's catch fire without the error message)
   - Removed unreachable `return null` after the throw
   - Added full error.message logging
   - saveGeoForIP now catches runwhois errors gracefully
══════════════════════════════════════════════════════ */
async function runwhois(host) {
    console.log(`${C.Green}[5ELG-WHOIS]${C.Reset} Fetching WHOIS for: ${C.Bold}${host}${C.Reset}`);
    try {
        const whoisData = await whois(host);

        const ipRecord = await IPINT.findOne({ where: { IP: host } });
        if (!ipRecord) {
            console.warn(`${C.Yellow}[5ELG-WHOIS] No IPINT record found for ${host} — skipping${C.Reset}`);
            return null;
        }

        const existingData = safeParse(ipRecord.DATA);
        const insertData   = { ...existingData, whois: whoisData };

        await IPINT.update({ DATA: insertData }, { where: { IP: host } });
        console.log(`${C.Green}[5ELG-WHOIS]${C.Reset} WHOIS saved for ${C.Bold}${host}${C.Reset}`);
        return insertData;

    } catch (error) {
        // Log the actual error message (was silent before due to throw+dead return)
        console.error(`${C.Red}[5ELG-WHOIS] Error for ${host}: ${error.message}${C.Reset}`);
        // Don't rethrow — let saveGeoForIP continue even if WHOIS fails
        return null;
    }
}

/* ══════════════════════════════════════════════════════
   saveGeoForIP — main entry point
   Handles GEO + WHOIS independently, neither blocks the other
══════════════════════════════════════════════════════ */
async function saveGeoForIP(ip) {
    if (!ip) return null;

    try {
        const [ipEntry] = await IPINT.findOrCreate({
            where:    { IP: ip },
            defaults: { MAC: null, DATA: null, GEO: null, SCAN: false, INTEL: null },
        });

        // ── 1. GEO: only fetch if not already stored ──
        let geoData = safeParse(ipEntry.GEO);

        if (!geoData || Object.keys(geoData).length === 0) {
            try {
                const response = await axios.get(
                    `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,query`,
                    { timeout: 8000 }
                );
                const d = response.data;

                if (d.status === 'success') {
                    geoData = {
                        country:     d.country     || '',
                        countryCode: d.countryCode || '',
                        regionName:  d.regionName  || '',
                        city:        d.city        || '',
                        lat:         d.lat         ?? null,
                        lon:         d.lon         ?? null,
                        isp:         d.isp         || '',
                        org:         d.org         || '',
                        query:       d.query       || ip,
                    };
                    await ipEntry.update({ GEO: geoData });
                    console.log(`${C.Green}[5ELG-GEO]${C.Reset} Saved: ${C.Bold}${ip}${C.Reset} → ${geoData.city}, ${geoData.countryCode}`);
                } else {
                    console.warn(`${C.Yellow}[5ELG-GEO] ip-api status="${d.status}" (${d.message || ''}) for ${ip}${C.Reset}`);
                }
            } catch (geoErr) {
                // GEO failure is non-fatal — log and continue to WHOIS
                console.warn(`${C.Yellow}[5ELG-GEO] GEO fetch failed for ${ip}: ${geoErr.message}${C.Reset}`);
            }
        } else {
            console.log(`${C.Dim}[5ELG-GEO] GEO already cached for ${ip}${C.Reset}`);
        }

        // ── 2. WHOIS: only fetch if not already stored ──
        const existingData = safeParse(ipEntry.DATA);
        if (!existingData.whois) {
            // runwhois now handles its own errors and never throws
            await runwhois(ip);
        } else {
            console.log(`${C.Dim}[5ELG-WHOIS] WHOIS already cached for ${ip}${C.Reset}`);
        }

        return geoData || null;

    } catch (err) {
        // Only outer DB errors land here now (findOrCreate failures etc.)
        console.error(`${C.Red}[5ELG-GEO] saveGeoForIP outer error for ${ip}: ${err.message}${C.Reset}`);
        return null;
    }
}

module.exports = { runwhois, geolocateAndUpdate, saveGeoForIP, fetchGeoLocation, banIP, unbanIP, getBlacklist };