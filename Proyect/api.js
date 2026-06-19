const express = require('express');
const router = express.Router();
const { Log, IPINT } = require('../Functions/db');
const { listUsers, createUser, updateUserPassword, deleteUser } = require('../Functions/auth');

const { runwhois, geolocateAndUpdate, saveGeoForIP, banIP, unbanIP, getBlacklist } = require('../Functions/scanners/ipinfo');
const { scanAndUpdateWithNmap } = require('../Functions/scanners/nmap');
const { updateSHODANIPData, updateCriminalIPData } = require('../Functions/scanners/shodan');

function safeResolvePath(basePath, targetPath) {
    const base = path.resolve(basePath);
    const resolved = path.resolve(base, targetPath);
    if (resolved !== base && !resolved.startsWith(base + path.sep)) {
        throw new Error('Invalid path');
    }
    return resolved;
}

// ── Importar todo lo necesario de utils ──────────────────────────────────────
const {
    generateCSV,
    generateCSVIP,
    generateCSVFingerprints,
    handleBackupLogs,
    handleFullBackup,
    clearLogs,
    getFingerprintRecordByID,
    processDealerData,      // usado en uploadCSVDealerData
    // Domain management
    getDomains,
    addDomain,
    findDomainById,
    activateDomain,
    removeDomain,           // nuevo — añadir a utils.js exports
    updateDomain,           // nuevo — añadir a utils.js exports
    deactivateDomain,       // nuevo — añadir a utils.js exports
} = require('../Functions/utils');

const csv     = require('csv-parser');          // necesario para uploadCSVDealerData
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const fsp     = require('fs').promises;
const dotenv  = require('dotenv');
const sequelize = require('sequelize');

const DEALERS_JSON_PATH = path.join(__dirname, '../Sources/data/dealers.json');
const CONFIGS_JSON_PATH = path.join(__dirname, '../Sources/data/configs.json');

dotenv.config();

// ── Multer storage ────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = process.env.UPLOAD_PATH || 'uploads';
        const id  = req.body.ID || 'default';
        const dir = path.join(uploadPath, id);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const suffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
        cb(null, `${file.fieldname}-${suffix}${path.extname(file.originalname)}`);
    },
});

const upload = multer({
    storage,
    limits: { fileSize: 500 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = /jpeg|jpg|png|gif|pdf|txt|docx|zip|csv|application\/octet-stream/;
        const ok = allowed.test(file.mimetype) && allowed.test(path.extname(file.originalname).toLowerCase());
        ok ? cb(null, true) : cb(new Error('Tipo de archivo no permitido.'));
    },
});

// Multer storage for dealer custom files → Dealers/custom/
const dealerCustomDir = path.join(__dirname, '../Dealers/custom');
const dealerFileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync(dealerCustomDir)) fs.mkdirSync(dealerCustomDir, { recursive: true });
        cb(null, dealerCustomDir);
    },
    filename: (req, file, cb) => {
        const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
        cb(null, safe);
    },
});
const dealerFileUpload = multer({
    storage: dealerFileStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        /\.(js|html|htm)$/.test(ext) ? cb(null, true) : cb(new Error('Only .js and .html files allowed'));
    },
});

// ════════════════════════════════════════════════════════════════════════════
//  OPTIONS HANDLERS
// ════════════════════════════════════════════════════════════════════════════
const apiOptionsHandlers = {

    // GET /api/options/env
    getENVVars: async (req, res) => {
        try {
            res.status(200).json(process.env);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching environment variables', details: err.message });
        }
    },

    // GET /api/options/getbackups
    getBackups: async (req, res) => {
        try {
            const backupsPath = process.env.BACKUP_PATH;
            if (!backupsPath) return res.status(500).json({ error: 'BACKUP_PATH is not defined' });

            fs.readdir(backupsPath, (err, files) => {
                if (err) return res.status(500).json({ error: 'Error reading backups directory', details: err.message });
                const backups = files.map(file => {
                    const stats = fs.statSync(path.join(backupsPath, file));
                    return { name: file, created: stats.birthtime, size: stats.size };
                });
                res.status(200).json(backups);
            });
        } catch (err) {
            res.status(500).json({ error: 'Error fetching backups', details: err.message });
        }
    },

    // ── helpers ──
    _readDealers: async () => {
        if (!fs.existsSync(DEALERS_JSON_PATH)) return [];
        const parsed = JSON.parse(await fsp.readFile(DEALERS_JSON_PATH, 'utf8'));
        return Array.isArray(parsed) ? parsed : (Array.isArray(parsed.domains) ? parsed.domains : []);
    },
    _writeDealers: async (arr) => {
        const dir = path.dirname(DEALERS_JSON_PATH);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        await fsp.writeFile(DEALERS_JSON_PATH, JSON.stringify(arr, null, 2), 'utf8');
    },

    // GET /api/options/dealers
    getDealers: async (req, res) => {
        try {
            res.status(200).json(await apiOptionsHandlers._readDealers());
        } catch (err) {
            res.status(500).json({ error: 'Error reading dealers.json', details: err.message });
        }
    },

    // POST /api/options/dealers
    addDealer: async (req, res) => {
        try {
            const dealers = await apiOptionsHandlers._readDealers();
            const newDealer = req.body;
            if (!newDealer.id) return res.status(400).json({ error: 'id is required' });
            if (dealers.find(d => d.id === newDealer.id))
                return res.status(400).json({ error: 'Dealer with this id already exists' });
            dealers.push(newDealer);
            await apiOptionsHandlers._writeDealers(dealers);
            res.status(201).json({ message: 'Dealer added successfully', dealer: newDealer });
        } catch (err) {
            res.status(500).json({ error: 'Error adding dealer', details: err.message });
        }
    },

    // PUT /api/options/dealers/:id
    updateDealer: async (req, res) => {
        try {
            const dealerId = req.params.id;
            const dealers = await apiOptionsHandlers._readDealers();
            const index = dealers.findIndex(d => d.id === dealerId);
            if (index === -1) return res.status(404).json({ error: 'Dealer not found' });
            dealers[index] = { ...dealers[index], ...req.body, id: dealerId };
            await apiOptionsHandlers._writeDealers(dealers);
            res.status(200).json({ message: 'Dealer updated successfully', dealer: dealers[index] });
        } catch (err) {
            res.status(500).json({ error: 'Error updating dealer', details: err.message });
        }
    },

    // DELETE /api/options/dealers/:id
    deleteDealer: async (req, res) => {
        try {
            const dealerId = req.params.id;
            const dealers = await apiOptionsHandlers._readDealers();
            const filtered = dealers.filter(d => d.id !== dealerId);
            if (filtered.length === dealers.length) return res.status(404).json({ error: 'Dealer not found' });
            await apiOptionsHandlers._writeDealers(filtered);
            res.status(200).json({ message: 'Dealer deleted successfully' });
        } catch (err) {
            res.status(500).json({ error: 'Error deleting dealer', details: err.message });
        }
    },

    // GET /api/options/dealer_files
    getDealerFiles: async (req, res) => {
        try {
            const dealersPath = process.env.DEALERS_PATH;
            if (!dealersPath) return res.status(500).json({ error: 'DEALERS_PATH is not defined' });

            fs.readdir(dealersPath, (err, files) => {
                if (err) return res.status(500).json({ error: 'Error reading dealers directory', details: err.message });
                const dealers = files.map(file => {
                    const stats = fs.statSync(path.join(dealersPath, file));
                    return {
                        name:      file,
                        extension: path.extname(file),
                        type:      stats.isFile() ? 'file' : 'directory',
                        size:      stats.size,
                    };
                });
                res.status(200).json(dealers);
            });
        } catch (err) {
            res.status(500).json({ error: 'Error fetching dealer files', details: err.message });
        }
    },

    // POST /api/options/dealers/upload-file
    uploadDealerFile: async (req, res) => {
        try {
            if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
            const relPath = `custom/${req.file.filename}`;
            res.status(200).json({ file: relPath, filename: req.file.filename });
        } catch (err) {
            res.status(500).json({ error: 'Upload failed', details: err.message });
        }
    },

    // GET /api/options/getdealer
    // GET /api/options/getdealer/:filename
    downloadDealer: async (req, res) => {
        try {
            const rawFilename = req.query.file || req.params.filename || '';
            if (!rawFilename) return res.status(400).json({ error: 'file query is required' });

            let filename = String(rawFilename);
            try { filename = decodeURIComponent(filename); } catch (ignore) {}

            const dealersPath = process.env.DEALERS_PATH;
            if (!dealersPath) return res.status(500).json({ error: 'DEALERS_PATH is not defined' });

            const filePath = safeResolvePath(dealersPath, filename);
            if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
                return res.status(404).json({ error: 'File not found' });
            }

            res.download(filePath, path.basename(filePath), err => {
                if (err) {
                    if (!res.headersSent) {
                        res.status(500).json({ error: 'Error downloading dealer file', details: err.message });
                    }
                }
            });
        } catch (err) {
            res.status(400).json({ error: 'Invalid file path', details: err.message });
        }
    },

    // ── Global Configs management ─────────────────────────────────────────────

    // GET /api/options/configs
    getConfigs: async (req, res) => {
        try {
            if (!fs.existsSync(CONFIGS_JSON_PATH)) return res.status(200).json({});
            const data = await fsp.readFile(CONFIGS_JSON_PATH, 'utf8');
            res.status(200).json(JSON.parse(data));
        } catch (err) {
            res.status(500).json({ error: 'Error reading configs.json', details: err.message });
        }
    },

    // PUT /api/options/configs
    updateConfigs: async (req, res) => {
        try {
            let configs = {};
            const dir = path.dirname(CONFIGS_JSON_PATH);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

            if (fs.existsSync(CONFIGS_JSON_PATH)) {
                configs = JSON.parse(await fsp.readFile(CONFIGS_JSON_PATH, 'utf8'));
            }

            // Actualizar / Mezclar (Merge) las configuraciones
            const updatedConfigs = { ...configs, ...req.body };
            await fsp.writeFile(CONFIGS_JSON_PATH, JSON.stringify(updatedConfigs, null, 4), 'utf8');
            res.status(200).json({ message: 'Configs updated successfully', configs: updatedConfigs });
        } catch (err) {
            res.status(500).json({ error: 'Error updating configs.json', details: err.message });
        }
    },

    // POST /api/options/domains/dealerdomain
    addDealerDomain: async (req, res) => {
        try {
            const { domain } = req.body;
            if (!domain) return res.status(400).json({ error: 'domain is required' });

            let configs = {};
            const dir = path.dirname(CONFIGS_JSON_PATH);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

            if (fs.existsSync(CONFIGS_JSON_PATH)) {
                configs = JSON.parse(await fsp.readFile(CONFIGS_JSON_PATH, 'utf8'));
            }

            if (!Array.isArray(configs.dealerdomains)) configs.dealerdomains = [];

            if (configs.dealerdomains.includes(domain)) {
                return res.status(400).json({ error: 'Dealer domain already exists in configs' });
            }

            configs.dealerdomains.push(domain);
            await fsp.writeFile(CONFIGS_JSON_PATH, JSON.stringify(configs, null, 4), 'utf8');
            res.status(201).json({ message: 'Dealer domain added successfully', dealerdomains: configs.dealerdomains });
        } catch (err) {
            res.status(500).json({ error: 'Error adding dealer domain', details: err.message });
        }
    },

    // ── Domain management (usa getDomains/addDomain/… de utils.js) ──────────

    // GET /api/options/domains
    getDomains: async (req, res) => {
        try {
            const domains = getDomains();          // utils.js: lee el JSON de config
            res.status(200).json({ domains });
        } catch (error) {
            console.error('[5ELG-DNS] getDomains error:', error.message);
            res.status(500).json({ error: 'Error fetching domains', details: error.message });
        }
    },

    // POST /api/options/domains
    // Body: { name, ip, status?, type?, ttl?, priority?, weight?, port?, txtData? }
    addDomain: async (req, res) => {
        const body = req.body || {};

        if (!body.name) return res.status(400).json({ error: 'name is required' });
        if (!body.ip)   return res.status(400).json({ error: 'ip (value/target) is required' });

        const newDomain = {
            name:   body.name.trim(),
            type:   (body.type || 'A').toUpperCase().trim(),
            ip:     body.ip.trim(),
            value:  (body.value || body.ip).trim(),
            status: body.status || 'inactive',
            ttl:    parseInt(body.ttl) || 3600,
        };
        if (body.priority != null) newDomain.priority = parseInt(body.priority);
        if (body.weight   != null) newDomain.weight   = parseInt(body.weight);
        if (body.port     != null) newDomain.port     = parseInt(body.port);
        if (body.txtData)          newDomain.txtData  = body.txtData.trim();

        try {
            addDomain(newDomain);       // utils.js: asigna id auto-incremental y guarda
            console.log(`[5ELG-DNS] Added ${newDomain.type} record: ${newDomain.name} → ${newDomain.value}`);
            res.status(201).json({ message: 'Domain added successfully', domain: newDomain });
        } catch (error) {
            console.error('[5ELG-DNS] addDomain error:', error.message);
            res.status(500).json({ error: 'Error adding domain', details: error.message });
        }
    },

    // GET /api/options/domains/:id
    findDomainById: async (req, res) => {
        const domainId = parseInt(req.params.id, 10);
        if (isNaN(domainId)) return res.status(400).json({ error: 'Invalid domain ID' });

        try {
            const domain = findDomainById(domainId);    // utils.js
            if (!domain) return res.status(404).json({ error: `Domain #${domainId} not found` });
            res.status(200).json(domain);
        } catch (error) {
            console.error('[5ELG-DNS] findDomainById error:', error.message);
            res.status(500).json({ error: 'Error finding domain', details: error.message });
        }
    },

    // PATCH /api/options/domains/:id/activate
    activateDomain: async (req, res) => {
        const domainId = parseInt(req.params.id, 10);
        if (isNaN(domainId)) return res.status(400).json({ error: 'Invalid domain ID' });

        try {
            const domain = findDomainById(domainId);    // utils.js
            if (!domain) return res.status(404).json({ error: `Domain #${domainId} not found` });
            if (domain.status === 'active') return res.status(400).json({ error: 'Domain is already active' });

            activateDomain(domainId);                   // utils.js
            console.log(`[5ELG-DNS] Domain #${domainId} activated`);
            res.status(200).json({ message: 'Domain activated successfully', domain: findDomainById(domainId) });
        } catch (error) {
            console.error('[5ELG-DNS] activateDomain error:', error.message);
            res.status(500).json({ error: 'Error activating domain', details: error.message });
        }
    },

    // PATCH /api/options/domains/:id/deactivate
    deactivateDomain: async (req, res) => {
        const domainId = parseInt(req.params.id, 10);
        if (isNaN(domainId)) return res.status(400).json({ error: 'Invalid domain ID' });

        try {
            const domain = findDomainById(domainId);
            if (!domain)                     return res.status(404).json({ error: `Domain #${domainId} not found` });
            if (domain.status === 'inactive') return res.status(400).json({ error: 'Domain is already inactive' });

            deactivateDomain(domainId);                 // utils.js (nuevo)
            console.log(`[5ELG-DNS] Domain #${domainId} deactivated`);
            res.status(200).json({ message: 'Domain deactivated successfully', domain: findDomainById(domainId) });
        } catch (error) {
            console.error('[5ELG-DNS] deactivateDomain error:', error.message);
            res.status(500).json({ error: 'Error deactivating domain', details: error.message });
        }
    },

    // DELETE /api/options/domains/:id
    deleteDomain: async (req, res) => {
        const domainId = parseInt(req.params.id, 10);
        if (isNaN(domainId)) return res.status(400).json({ error: 'Invalid domain ID' });

        try {
            const domain = findDomainById(domainId);
            if (!domain) return res.status(404).json({ error: `Domain #${domainId} not found` });

            const deleted = removeDomain(domainId);     // utils.js (nuevo)
            if (!deleted) return res.status(500).json({ error: 'Failed to delete domain from config' });

            console.log(`[5ELG-DNS] Domain #${domainId} (${domain.name}) deleted`);
            res.status(200).json({ message: `Domain #${domainId} deleted successfully` });
        } catch (error) {
            console.error('[5ELG-DNS] deleteDomain error:', error.message);
            res.status(500).json({ error: 'Error deleting domain', details: error.message });
        }
    },

    // PUT /api/options/domains/:id  — merge parcial
    updateDomain: async (req, res) => {
        const domainId = parseInt(req.params.id, 10);
        if (isNaN(domainId)) return res.status(400).json({ error: 'Invalid domain ID' });

        const updates = req.body || {};
        if (!Object.keys(updates).length) return res.status(400).json({ error: 'No fields to update' });

        try {
            const domain = findDomainById(domainId);
            if (!domain) return res.status(404).json({ error: `Domain #${domainId} not found` });

            if (updates.type) updates.type = updates.type.toUpperCase();
            const updated = updateDomain(domainId, updates);   // utils.js (nuevo)
            console.log(`[5ELG-DNS] Domain #${domainId} updated:`, Object.keys(updates).join(', '));
            res.status(200).json({ message: 'Domain updated successfully', domain: updated });
        } catch (error) {
            console.error('[5ELG-DNS] updateDomain error:', error.message);
            res.status(500).json({ error: 'Error updating domain', details: error.message });
        }
    },
};

// ════════════════════════════════════════════════════════════════════════════
//  MAIN API HANDLERS
// ════════════════════════════════════════════════════════════════════════════
const apiHandlers = {

    // GET /api/out/backup
    generateCsvLogs: async (req, res) => {
        try {
            const csvFilePath = await handleBackupLogs();   // utils.js
            await fsp.access(csvFilePath);
            const csvData = await fsp.readFile(csvFilePath, 'utf8');
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename=logs_backup.csv');
            res.send(csvData);
        } catch (err) {
            console.error('Error generating CSV logs:', err);
            res.status(500).json({ error: 'Error generating CSV logs', details: err.message });
        }
    },

    // DELETE /api/purge
    clearLogs: async (req, res) => {
        const id = req.query.id || null;
        try {
            await clearLogs(id);                            // utils.js
            res.json({ message: id ? `Log with ID ${id} cleared successfully.` : 'All logs cleared successfully.' });
        } catch (err) {
            res.status(500).json({ error: 'Error clearing logs', details: err });
        }
    },

    // DELETE /api/purge/dns|icmp|ws|http
    purgeByType: async (req, res) => {
        const type = req.params.type;
        const dlMap = { dns: 'DNS.LOG', icmp: 'ICMP.LOG', ws: 'WS-REQUEST' };
        try {
            let deleted;
            if (dlMap[type]) {
                deleted = await Log.destroy({ where: { Dl: dlMap[type] } });
            } else if (type === 'http') {
                const { Op: Op2 } = require('sequelize');
                deleted = await Log.destroy({ where: { Dl: { [Op2.notIn]: Object.values(dlMap) } } });
            } else {
                return res.status(400).json({ error: 'Unknown traffic type' });
            }
            res.json({ message: `Purged ${deleted} ${type.toUpperCase()} records.`, deleted });
        } catch (err) {
            res.status(500).json({ error: 'Purge failed', details: err.message });
        }
    },

    // DELETE /api/purge/ips  — wipe entire IPINT table
    purgeIpDb: async (req, res) => {
        try {
            const deleted = await IPINT.destroy({ where: {}, truncate: true });
            res.json({ message: 'IP database cleared.', deleted });
        } catch (err) {
            res.status(500).json({ error: 'Failed to clear IP database', details: err.message });
        }
    },

    // DELETE /api/purge/dealers  — reset dealers.json to []
    purgeAllDealers: async (req, res) => {
        try {
            fs.writeFileSync(DEALERS_JSON_PATH, JSON.stringify([], null, 2), 'utf8');
            res.json({ message: 'All dealers deleted.' });
        } catch (err) {
            res.status(500).json({ error: 'Failed to delete dealers', details: err.message });
        }
    },

    // GET /api/out/dealers  — download dealers.json
    downloadDealersJson: async (req, res) => {
        try {
            if (!fs.existsSync(DEALERS_JSON_PATH)) return res.status(404).json({ error: 'dealers.json not found' });
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename=dealers_${Date.now()}.json`);
            res.send(fs.readFileSync(DEALERS_JSON_PATH, 'utf8'));
        } catch (err) {
            res.status(500).json({ error: 'Failed to download dealers', details: err.message });
        }
    },

    // GET /api/out/ips  — download IPINT as CSV
    downloadIpDb: async (req, res) => {
        try {
            const records = await IPINT.findAll().then(r => r.map(x => x.toJSON()));
            if (!records.length) return res.status(404).json({ error: 'No IP records' });
            const csv = await generateCSVIP(records);
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=ipint_${Date.now()}.csv`);
            res.send(csv);
        } catch (err) {
            res.status(500).json({ error: 'Failed to export IP database', details: err.message });
        }
    },

    // GET /api/out/full-backup  — ZIP with all tables as CSVs
    fullBackup: async (req, res) => {
        try {
            await handleFullBackup(res);
        } catch (err) {
            console.error('[5ELG] Full backup error:', err.message);
            if (!res.headersSent) res.status(500).json({ error: 'Full backup failed', details: err.message });
        }
    },

    // GET /api/count
    countDealers: async (req, res) => {
        try {
            const result = await Log.findAll({
                attributes: ['Dl', [sequelize.fn('COUNT', sequelize.col('Dl')), 'count']],
                group: ['Dl'],
            });
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: 'Error counting dealers', details: err.message });
        }
    },

    // POST /api/out/upload  (CSV dealer proxy data)
    uploadCSVDealerData: (req, res) => {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });

        const results = [];
        fs.createReadStream(req.file.path)
            .pipe(csv())
            .on('data', (data) => {
                results.push({
                    fpRequest:   data.FP_REQUEST,
                    encodedScr:  data.SCREEN_ENCODED,
                    encodedPage: data.HTML_ENCODED,
                    jsData:      data.JS_DATA,
                    encodedReq:  Buffer.from(JSON.stringify(data.encoded_req)).toString('base64'),
                    rts:         data.TS,
                    ip:          data.IP,
                    userAgent:   decodeURIComponent(data.UA || ''),
                    fpUser:      data.FP_USER,
                    fpBrowser:   data.FP_BROWSER,
                });
            })
            .on('end', async () => {
                try {
                    for (const dealerData of results) {
                        processDealerData(dealerData);  // utils.js
                    }
                    res.status(200).json({ message: 'CSV processed successfully', imported: results.length });
                } catch (err) {
                    console.error('[!] Error saving CSV data:', err.message);
                    res.status(500).json({ error: 'Error saving data to database', details: err.message });
                }
            })
            .on('error', (err) => {
                console.error('[!] Error processing CSV:', err.message);
                res.status(500).json({ error: 'Error processing CSV file', details: err.message });
            });
    },

    // GET /api/out/info
    csvClientInfo: async (req, res) => {
        const { id } = req.query;
        if (!id) return res.status(400).json({ error: 'ID is required' });
        try {
            const csvData = await generateCSV({ id });      // utils.js
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=client_${id}_info.csv`);
            res.send(csvData);
        } catch (err) {
            res.status(500).json({ error: 'Error generating client CSV', details: err.message });
        }
    },

    // GET /api/out/all
    csvAllClients: async (req, res) => {
        try {
            const csvData = await generateCSV();            // utils.js
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename=all_clients.csv');
            res.send(csvData);
        } catch (err) {
            res.status(500).json({ error: 'Error generating CSV', details: err.message });
        }
    },

    // GET /api/getfiles/:ID
    getFileFromID: async (req, res) => {
        try {
            const { ID } = req.params;
            const dir = path.join(process.env.UPLOAD_PATH || 'uploads', ID);
            if (!fs.existsSync(dir)) return res.status(404).json({ message: 'Folder not found.' });

            const files = fs.readdirSync(dir).map(file => {
                const stats = fs.statSync(path.join(dir, file));
                return { filename: file, size: stats.size, creationTime: stats.birthtime, modificationTime: stats.mtime };
            });
            res.status(200).json({ message: 'Files retrieved successfully.', files });
        } catch (err) {
            res.status(500).json({ message: 'Error retrieving files.', error: err.message });
        }
    },

    // GET /api/out/client
    getClientFInfo: async (req, res) => {
        const { fu } = req.query;
        if (!fu) return res.status(400).json({ error: 'Fu is required' });
        try {
            const logs = await Log.findAll({ where: { Fu: fu } });
            if (!logs.length) return res.status(404).json({ error: 'No logs found for this Fu' });
            res.json(logs);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching logs for Fu', details: err.message });
        }
    },

    // GET /api/last7
    last7Logs: async (req, res) => {
        try {
            // Exclude heavy BLOB columns — html/screen are fetched individually on demand
            const logs = await Log.findAll({
                attributes: { exclude: ['html', 'screen'] },
                limit: 7000,
                order: [['id', 'DESC']],
            });
            res.json(logs);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching logs', details: err.message });
        }
    },

    // GET /api/total
    totalLogs: async (req, res) => {
        try {
            res.json({ total_logs: await Log.count() });
        } catch (err) {
            res.status(500).json({ error: 'Error counting logs', details: err.message });
        }
    },

    // GET /api/dealers
    logsByDealer: async (req, res) => {
        try {
            const result = await Log.findAll({
                attributes: ['Dl', [sequelize.fn('COUNT', sequelize.col('Dl')), 'count']],
                group: ['Dl'],
            });
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching logs by dealer', details: err.message });
        }
    },

    // GET /api/ip
    logsByIP: async (req, res) => {
        try {
            const result = await Log.findAll({
                attributes: ['Ip', [sequelize.fn('COUNT', sequelize.col('Ip')), 'count']],
                group: ['Ip'],
            });
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching logs by IP', details: err.message });
        }
    },

    // POST /api/upload
    upload: async (req, res) => {
        try {
            if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
            res.status(200).json({ message: 'File uploaded successfully.', file: {
                originalname: req.file.originalname,
                filename:     req.file.filename,
                path:         req.file.path,
                size:         req.file.size,
            }});
        } catch (err) {
            res.status(500).json({ message: 'Error uploading file.', error: err.message });
        }
    },

    // POST /api/uploads
    uploads: async (req, res) => {
        try {
            if (!req.files?.length) return res.status(400).json({ message: 'No files uploaded.' });
            res.status(200).json({
                message: 'Files uploaded successfully.',
                files: req.files.map(f => ({ originalname: f.originalname, filename: f.filename, size: f.size })),
            });
        } catch (err) {
            res.status(500).json({ message: 'Error uploading files.', error: err.message });
        }
    },

    // GET /api/files
    getfiles: async (req, res) => {
        try {
            const uploadPath = process.env.UPLOAD_PATH;
            const folders = fs.readdirSync(uploadPath, { withFileTypes: true }).filter(d => d.isDirectory());
            const fileDetails = [];
            for (const folder of folders) {
                const folderPath = path.join(uploadPath, folder.name);
                fs.readdirSync(folderPath, { withFileTypes: true }).forEach(file => {
                    if (!file.isFile()) return;
                    const stats = fs.statSync(path.join(folderPath, file.name));
                    fileDetails.push({
                        name: file.name, type: path.extname(file.name) || 'unknown',
                        size: stats.size, lastModified: stats.mtime, origin: folder.name,
                    });
                });
            }
            res.status(200).json({ files: fileDetails });
        } catch (err) {
            res.status(500).json({ message: 'Error listing files.', error: err.message });
        }
    },

    // GET /api/file/:filename
    getSingleFile: async (req, res) => {
        const filePath = path.join(process.env.UPLOAD_PATH || 'uploads', req.params.filename);
        if (!fs.existsSync(filePath)) return res.status(404).json({ message: 'File not found.' });
        res.download(filePath, req.params.filename, err => {
            if (err) res.status(500).json({ message: 'Error downloading file.', error: err.message });
        });
    },

    // GET /api/getfinger/:userId
    FingerByUserID: async (req, res) => {
        try {
            const result = await getFingerprintRecordByID(req.params.userId);  // utils.js
            res.status(200).json(result);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching fingerprint record', details: err.message });
        }
    },

    // GET /api/fbro
    FingerBrows: async (req, res) => {
        try {
            const result = await Log.findAll({
                attributes: ['Fb', [sequelize.fn('COUNT', sequelize.col('Fb')), 'count']],
                group: ['Fb'],
            });
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching browser fingerprints', details: err.message });
        }
    },

    // GET /api/fus
    fingersUsers: async (req, res) => {
        try {
            const result = await Log.findAll({
                attributes: ['Fu', [sequelize.fn('COUNT', sequelize.col('Fu')), 'count']],
                group: ['Fu'],
            });
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching user fingerprints', details: err.message });
        }
    },

    // GET /api/getfinger/getlogs/:userId
    logbyFU: async (req, res) => {
        try {
            const result = await Log.findAll({ where: { Fu: req.params.userId } });
            // Strip heavy BLOBs from JSON payload; expose boolean flags instead
            const plain = result.map(r => {
                const d = r.get({ plain: true });
                const hasScreen = d.screen != null;
                const hasHtml   = d.html   != null;
                delete d.screen;
                delete d.html;
                d.hasScreen = hasScreen;
                d.hasHtml   = hasHtml;
                return d;
            });
            res.json(plain);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching logs by Fu', details: err.message });
        }
    },

    // GET /api/screenshot/:fr  — serves PNG image for a given Fr hash
    screenshot: async (req, res) => {
        const { fr } = req.params;
        if (!/^[A-Za-z0-9_-]{1,64}$/.test(fr)) return res.status(400).send('Invalid');
        const screenshotDir = path.join(__dirname, '../Sources/screenshotsB64');
        const shotPath = path.join(screenshotDir, `${fr}.shot`);
        let encoded = null;
        if (fs.existsSync(shotPath)) {
            encoded = fs.readFileSync(shotPath, 'utf8');
        } else {
            try {
                const record = await Log.findOne({ attributes: ['screen'], where: { Fr: fr } });
                if (record?.screen) encoded = Buffer.from(record.screen).toString('utf8');
            } catch (_) {}
        }
        if (!encoded) return res.status(404).send('No screenshot');
        try {
            const base64 = decodeURIComponent(encoded);
            const png = Buffer.from(base64, 'base64');
            res.set('Content-Type', 'image/png');
            res.set('Cache-Control', 'public, max-age=86400');
            return res.send(png);
        } catch (e) {
            return res.status(500).send('Decode error');
        }
    },
    // GET /api/getfinger/getDEaler/:Dealer
    logbyDealer: async (req, res) => {
        try {
            const result = await Log.findAll({ where: { Dl: req.params.Dl } });
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching logs by IP', details: err.message });
        }
    },
    // GET /api/getfinger/getIPlogs/:IPD
    logbyIP: async (req, res) => {
        try {
            const result = await Log.findAll({ where: { Ip: req.params.IPD } });
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: 'Error fetching logs by IP', details: err.message });
        }
    },
};

// ════════════════════════════════════════════════════════════════════════════
//  SCANNER / OSINT HANDLERS
// ════════════════════════════════════════════════════════════════════════════
const apiScannersHandlers = {

    runScanner: async (req, res) => {
        const { IP } = req.body;
        if (!IP) return res.status(400).json({ error: 'Missing IP in request body.' });
        try {
            const nmapResults = await scanAndUpdateWithNmap(IP);
            await runwhois(IP);
            res.status(200).json({ message: `Scanner tasks for IP: ${IP} completed.`, data: nmapResults });
        } catch (error) {
            console.error('[5ELG-SCANNER] Error:', error);
            res.status(500).json({ error: 'Internal Server Error', details: error.message });
        }
    },

    geoBatch: async (req, res) => {
        try {
            const ips = req.body.ips;
            if (!Array.isArray(ips) || !ips.length) return res.status(400).json({ error: 'Missing ips array in body' });

            const clean   = [...new Set(ips.map(s => String(s).trim()).filter(Boolean))].slice(0, 200);
            const entries = await IPINT.findAll({ where: { IP: clean }, raw: true });

            const result = entries.map(e => {
                let geo = {};
                try { if (e.GEO) geo = typeof e.GEO === 'string' ? JSON.parse(e.GEO) : e.GEO; } catch(_) {}
                return {
                    query:       e.IP,
                    countryCode: geo.countryCode || geo.country  || '',
                    country:     geo.country     || geo.countryCode || '',
                    regionName:  geo.regionName  || geo.region   || '',
                    city:        geo.city        || '',
                    org:         geo.org         || geo.isp      || geo.as || '',
                    isp:         geo.isp         || geo.org      || '',
                    lat:         geo.lat         || null,
                    lon:         geo.lon         || geo.lng      || null,
                };
            });
            res.json(result);
        } catch (err) {
            console.error('[5ELG-GEO] geoBatch error:', err.message);
            res.status(500).json({ error: 'geoBatch failed', details: err.message });
        }
    },

    runGeo: async (req, res) => {
        const IP = (req.body && req.body.IP) || req.query.IP;
        if (!IP) return res.status(400).json({ error: 'Missing IP' });
        try {
            await IPINT.findOrCreate({ where: { IP }, defaults: { MAC: null, DATA: null, GEO: null, SCAN: false, INTEL: null } });
            const geoData = await geolocateAndUpdate(IP);
            if (!geoData) return res.status(200).json({ status: 'no_data', IP });
            res.status(200).json({ status: 'success', IP, geo: geoData });
        } catch (err) {
            console.error('[5ELG-GEO] runGeo error:', err.message);
            res.status(500).json({ error: err.message });
        }
    },

    runOSINT: async (req, res) => {
        const { IP } = req.body;
        if (!IP) return res.status(400).json({ status: 'error', message: 'No IP provided.' });
        try {
            console.log(`[OSINT] Starting analysis for IP: ${IP}`);
            await updateSHODANIPData(IP);
            await updateCriminalIPData(IP);
            res.status(200).json({ status: 'success', message: `OSINT completed for IP: ${IP}` });
        } catch (error) {
            console.error(`[OSINT] Error for IP: ${error.message}`);
            res.status(500).json({ status: 'error', message: error.message });
        }
    },

    // POST /api/ips/ban
    banIP: async (req, res) => {
        const { IP } = req.body;
        if (!IP) return res.status(400).json({ error: 'IP address is required' });
        try {
            const result = await banIP(IP);
            res.status(200).json(result);
        } catch (err) {
            console.error(`[5ELG-BAN] banIP error: ${err.message}`);
            res.status(500).json({ error: err.message });
        }
    },

    // POST /api/ips/unban
    unbanIP: async (req, res) => {
        const { IP } = req.body;
        if (!IP) return res.status(400).json({ error: 'IP address is required' });
        try {
            const result = await unbanIP(IP);
            res.status(200).json(result);
        } catch (err) {
            console.error(`[5ELG-BAN] unbanIP error: ${err.message}`);
            res.status(500).json({ error: err.message });
        }
    },

    // GET /api/ips/blacklist
    getBlacklist: (req, res) => {
        try {
            res.status(200).json(getBlacklist());
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    },

    geoFill: (() => {
        let _running = false;
        const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fc|fd)/i;
        return async (req, res) => {
            if (_running) return res.json({ running: true, message: 'Geo fill already in progress' });
            try {
                const [allIps, existing] = await Promise.all([
                    Log.findAll({ attributes: ['Ip'], raw: true }),
                    IPINT.findAll({ attributes: ['IP'], raw: true }),
                ]);
                const knownSet = new Set(existing.map(e => e.IP));
                const todo = [...new Set(allIps.map(l => l.Ip).filter(ip => ip && !PRIVATE.test(ip) && !knownSet.has(ip)))];
                res.json({ queued: todo.length, message: 'Geo fill started in background' });

                if (!todo.length) return;
                _running = true;
                console.log(`[5ELG-GEOFILL] Starting geo fill for ${todo.length} IPs`);
                let done = 0;
                for (const ip of todo) {
                    try { await geolocateAndUpdate(ip); } catch (_) {}
                    done++;
                    if (done % 20 === 0) console.log(`[5ELG-GEOFILL] ${done}/${todo.length}`);
                    await new Promise(r => setTimeout(r, 1400)); // ip-api.com: 45 req/min free
                }
                console.log(`[5ELG-GEOFILL] Complete: ${done} IPs processed`);
                _running = false;
            } catch (err) {
                _running = false;
                if (!res.headersSent) res.status(500).json({ error: err.message });
                console.error('[5ELG-GEOFILL] Error:', err.message);
            }
        };
    })(),

    listsIPs: async (req, res) => {
        try {
            res.status(200).json(await IPINT.findAll({ where: { SCAN: true } }));
        } catch (error) {
            res.status(500).json({ error: 'Error listing IPs', details: error.message });
        }
    },

    // POST /api/ips/batch-info  — returns IPINT records for a list of IPs
    batchIPInfo: async (req, res) => {
        const { ips } = req.body;
        if (!Array.isArray(ips) || !ips.length) return res.json([]);
        try {
            const { Op } = require('sequelize');
            const records = await IPINT.findAll({ where: { IP: { [Op.in]: ips } } });
            res.json(records.map(r => r.get({ plain: true })));
        } catch (err) {
            res.status(500).json({ error: 'Error fetching IP batch info', details: err.message });
        }
    },

    infoIP: async (req, res) => {
        const { ID } = req.query;
        if (!ID) return res.status(400).json({ error: 'ID is required' });
        try {
            const ipInfo = await IPINT.findOne({ where: { ID } });
            if (!ipInfo) return res.status(404).json({ error: 'IP not found' });
            res.status(200).json(ipInfo);
        } catch (error) {
            res.status(500).json({ error: 'Error fetching IP info', details: error.message });
        }
    },

    checkOrCreateIP: async (req, res) => {
        const { IP } = req.body;
        if (!IP) return res.status(400).json({ error: 'IP is required.' });
        try {
            const [ipEntry, created] = await IPINT.findOrCreate({
                where: { IP },
                defaults: { MAC: null, DATA: null, GEO: null, SCAN: false, INTEL: null },
            });
            if (!created && ipEntry.SCAN === false) {
                ipEntry.SCAN = true;
            }
            await ipEntry.save();
            res.status(200).json({ message: created ? 'IP created.' : 'IP already exists.', ipEntry });
        } catch (error) {
            res.status(500).json({ error: 'Error checking or creating IP.', details: error.message });
        }
    },

    updateIPField: async (req, res) => {
        const { id }          = req.query;
        const { field, value } = req.body;
        if (!id || !field) return res.status(400).json({ error: 'ID and field are required.' });

        const validFields = ['MAC', 'DATA', 'GEO', 'SCAN', 'INTEL'];
        if (!validFields.includes(field)) return res.status(400).json({ error: `Invalid field. Valid: ${validFields.join(', ')}` });

        try {
            const ipEntry = await IPINT.findByPk(id);
            if (!ipEntry) return res.status(404).json({ error: 'IP entry not found.' });

            let parsedValue = value;
            if (['DATA','GEO','INTEL'].includes(field) && typeof value === 'string') {
                try { parsedValue = JSON.parse(value); } catch(_) {}
            }
            if (['DATA','GEO','INTEL'].includes(field)) {
                let existing = ipEntry[field];
                try { if (typeof existing === 'string') existing = JSON.parse(existing); } catch(_) { existing = {}; }
                if (!existing || typeof existing !== 'object') existing = {};
                if (typeof parsedValue === 'object' && parsedValue !== null) parsedValue = { ...existing, ...parsedValue };
            }

            ipEntry[field] = parsedValue;
            await ipEntry.save();
            res.status(200).json({ message: 'IP field updated.', ipEntry });
        } catch (error) {
            res.status(500).json({ error: 'Error updating IP field.', details: error.message });
        }
    },

    updateIP: async (req, res) => {
        const id = req.query.id;
        if (!id) return res.status(400).json({ message: 'Missing ID parameter.' });
        try {
            const ipEntry = await IPINT.findByPk(id);
            if (!ipEntry) return res.status(404).json({ message: `IP entry ${id} not found.` });

            const mergeIfNeeded = (fieldName, newVal) => {
                if (newVal === undefined) return ipEntry[fieldName];
                let p = newVal;
                try { if (typeof p === 'string') p = JSON.parse(p); } catch(_) {}
                let existing = ipEntry[fieldName];
                try { if (typeof existing === 'string') existing = JSON.parse(existing); } catch(_) { existing = {}; }
                if (!existing || typeof existing !== 'object') existing = {};
                return (typeof p === 'object' && p !== null) ? { ...existing, ...p } : p;
            };

            const { IP, MAC, DATA, GEO, SCAN, INTEL } = req.body;
            await ipEntry.update({
                IP:    IP    || ipEntry.IP,
                MAC:   MAC   || ipEntry.MAC,
                DATA:  mergeIfNeeded('DATA',  DATA),
                GEO:   mergeIfNeeded('GEO',   GEO),
                SCAN:  typeof SCAN === 'boolean' ? SCAN : ipEntry.SCAN,
                INTEL: mergeIfNeeded('INTEL', INTEL),
            });
            res.status(200).json({ message: `IP entry ${id} updated.`, updatedEntry: ipEntry });
        } catch (error) {
            res.status(500).json({ message: 'Error updating IP.', error: error.message });
        }
    },

    scannIP: async (req, res) => {
        const { IP } = req.body;
        if (!IP) return res.status(400).json({ error: 'IP address is required' });
        try {
            const ipEntry = await IPINT.findOne({ where: { IP } });
            if (!ipEntry) return res.status(404).json({ error: 'IP not found' });
            ipEntry.SCAN = true;
            await ipEntry.save();
            res.status(200).json({ message: `IP ${IP} has been scanned`, ipEntry });
        } catch (error) {
            res.status(500).json({ error: 'Error scanning IP', details: error.message });
        }
    },

    deleteIP: async (req, res) => {
        const { ID } = req.body;
        if (!ID) return res.status(400).json({ error: 'ID is required' });
        try {
            const result = await IPINT.destroy({ where: { ID } });
            if (!result) return res.status(404).json({ error: 'IP not found' });
            res.status(200).json({ message: `IP ${ID} has been deleted` });
        } catch (error) {
            res.status(500).json({ error: 'Error deleting IP', details: error.message });
        }
    },

    purgeIPs: async (req, res) => {
        try {
            await IPINT.destroy({ where: {}, truncate: true });
            console.log('[5ELG-API] All IPs purged');
            res.status(200).json({ message: 'All IPs purged successfully.' });
        } catch (error) {
            res.status(500).json({ error: 'Error purging IPs', details: error.message });
        }
    },

    allIPs: async (req, res) => {
        try {
            res.status(200).json({ ips: await IPINT.findAll() });
        } catch (error) {
            res.status(500).json({ error: 'Error fetching IPs', details: error.message });
        }
    },

    ipout: async (req, res) => {
        const { IP } = req.body;
        if (!IP) return res.status(400).json({ error: 'IP address is required' });
        try {
            const ipEntry = await IPINT.findOne({ where: { IP } });
            if (!ipEntry) return res.status(404).json({ error: 'IP not found' });
            res.status(200).json({ ip: ipEntry });
        } catch (error) {
            res.status(500).json({ error: 'Error fetching IP info', details: error.message });
        }
    },
};

// ════════════════════════════════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════════════════════════════════

// Logs / data
router.delete('/purge',                    apiHandlers.clearLogs);
router.delete('/purge/type/:type',         apiHandlers.purgeByType);
router.delete('/purge/ips',                apiHandlers.purgeIpDb);
router.delete('/purge/dealers',            apiHandlers.purgeAllDealers);
router.get('/out/backup',                  apiHandlers.generateCsvLogs);
router.get('/out/full-backup',             apiHandlers.fullBackup);
router.get('/out/dealers',                 apiHandlers.downloadDealersJson);
router.get('/out/ips',                     apiHandlers.downloadIpDb);
router.get('/count',                 apiHandlers.countDealers);
router.get('/out/info',              apiHandlers.csvClientInfo);
router.get('/out/all',               apiHandlers.csvAllClients);
router.get('/out/client',            apiHandlers.getClientFInfo);
router.post('/out/upload',           upload.single('file'), apiHandlers.uploadCSVDealerData);

// File upload
router.post('/upload',               upload.single('file'),  apiHandlers.upload);
router.post('/uploads',              upload.array('files'),  apiHandlers.uploads);
router.get('/files',                 apiHandlers.getfiles);
router.get('/file/:filename',        apiHandlers.getSingleFile);
router.get('/getfiles/:ID',          apiHandlers.getFileFromID);

// Logs queries
router.get('/last7',                 apiHandlers.last7Logs);

router.get('/total',                 apiHandlers.totalLogs);
router.get('/dealers',               apiHandlers.logsByDealer);
router.get('/ip',                    apiHandlers.logsByIP);
router.get('/fbro',                  apiHandlers.FingerBrows);
router.get('/fus',                   apiHandlers.fingersUsers);
router.get('/getfinger/getlogs/:userId',  apiHandlers.logbyFU);
router.get('/getfinger/getIPlogs/:IPD',   apiHandlers.logbyIP);
router.get('/getfinger/getDealerlogs/:Dealer',   apiHandlers.logbyDealer);
router.get('/getfinger/:userId',          apiHandlers.FingerByUserID);
router.get('/screenshot/:fr',             apiHandlers.screenshot);

// Options / config
router.get('/options/env',                          apiOptionsHandlers.getENVVars);
router.get('/options/getbackups',                   apiOptionsHandlers.getBackups);
router.get('/options/dealers',                      apiOptionsHandlers.getDealers);
router.post('/options/dealers',                                          apiOptionsHandlers.addDealer);
router.post('/options/dealers/upload-file', dealerFileUpload.single('file'), apiOptionsHandlers.uploadDealerFile);
router.put('/options/dealers/:id',                                           apiOptionsHandlers.updateDealer);
router.delete('/options/dealers/:id',                                        apiOptionsHandlers.deleteDealer);
router.get('/options/dealer_files',                 apiOptionsHandlers.getDealerFiles);
router.get('/options/getdealer',                    apiOptionsHandlers.downloadDealer);
router.get('/options/getdealer/:filename',          apiOptionsHandlers.downloadDealer);
// Domains
router.get   ('/options/domains',                   apiOptionsHandlers.getDomains);
router.post  ('/options/domains',                   apiOptionsHandlers.addDomain);

// Global Configs
router.get   ('/options/configs',                   apiOptionsHandlers.getConfigs);
router.put   ('/options/configs',                   apiOptionsHandlers.updateConfigs);
router.post  ('/options/domains/dealerdomain',      apiOptionsHandlers.addDealerDomain);

router.get   ('/options/domains/:id',               apiOptionsHandlers.findDomainById);
router.patch ('/options/domains/:id/activate',      apiOptionsHandlers.activateDomain);
router.patch ('/options/domains/:id/deactivate',    apiOptionsHandlers.deactivateDomain);  // nuevo
router.put   ('/options/domains/:id',               apiOptionsHandlers.updateDomain);       // nuevo
router.delete('/options/domains/:id',               apiOptionsHandlers.deleteDomain);       // nuevo

// IPs / OSINT
router.get  ('/ips/lists',           apiScannersHandlers.listsIPs);
router.get  ('/ips/info',            apiScannersHandlers.infoIP);
router.post ('/ips/scann',           apiScannersHandlers.scannIP);
router.post ('/ips/delete',          apiScannersHandlers.deleteIP);
router.post ('/ips/purge',           apiScannersHandlers.purgeIPs);
router.post ('/ips/out/all',         apiScannersHandlers.allIPs);
router.post ('/ips/out/ip',          apiScannersHandlers.ipout);
router.post ('/ips/batch-info',       apiScannersHandlers.batchIPInfo);
router.post ('/ips/check',           apiScannersHandlers.checkOrCreateIP);
router.post ('/ips/add',             apiScannersHandlers.updateIP);
router.post ('/ips/update',          apiScannersHandlers.updateIPField);
router.post ('/ips/ban',             apiScannersHandlers.banIP);
router.post ('/ips/unban',           apiScannersHandlers.unbanIP);
router.get  ('/ips/blacklist',       apiScannersHandlers.getBlacklist);
router.post ('/ips/geo-fill',        apiScannersHandlers.geoFill);
router.post ('/geo/batch',           apiScannersHandlers.geoBatch);
router.post ('/ips/run/scann',       apiScannersHandlers.runScanner);
router.post ('/ips/run/geo',         apiScannersHandlers.runGeo);
router.get  ('/ips/geo',             apiScannersHandlers.runGeo);   // GET /api/ips/geo?IP=1.2.3.4
router.post ('/ips/run/osint',       apiScannersHandlers.runOSINT);

// ── User management (admin only) ──────────────────────────────────────────────
function adminOnly(req, res, next) {
    if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
}

// GET /api/users — list all users (no passwords)
router.get('/users', adminOnly, (req, res) => {
    try { res.json(listUsers()); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/users — create user
// body: { username, password, role?, displayName? }
router.post('/users', adminOnly, (req, res) => {
    const { username, password, role, displayName } = req.body || {};
    if (!username || !password)
        return res.status(400).json({ error: 'username and password required' });
    const allowed = ['admin', 'viewer'];
    if (role && !allowed.includes(role))
        return res.status(400).json({ error: `role must be one of: ${allowed.join(', ')}` });
    try {
        const user = createUser(username, password, role || 'viewer', { displayName });
        console.log(`[AUTH] User created: ${username} by ${req.user.username}`);
        res.status(201).json(user);
    } catch (e) {
        res.status(409).json({ error: e.message });
    }
});

// PATCH /api/users/:username/password — change password
// body: { password }
router.patch('/users/:username/password', adminOnly, (req, res) => {
    const { username } = req.params;
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ error: 'password required' });
    try {
        updateUserPassword(username, password);
        console.log(`[AUTH] Password changed for ${username} by ${req.user.username}`);
        res.json({ ok: true });
    } catch (e) {
        res.status(404).json({ error: e.message });
    }
});

// DELETE /api/users/:username — delete user
router.delete('/users/:username', adminOnly, (req, res) => {
    const { username } = req.params;
    if (username === req.user.username)
        return res.status(400).json({ error: 'Cannot delete your own account' });
    try {
        deleteUser(username);
        console.log(`[AUTH] User deleted: ${username} by ${req.user.username}`);
        res.json({ ok: true });
    } catch (e) {
        res.status(404).json({ error: e.message });
    }
});

console.log('[5ELG-API] API functions loaded successfully');
module.exports = router;