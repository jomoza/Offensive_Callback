const { FINGERDATA, IPINT, Log, Op } = require('./db');
const archiver = require('archiver');
const fs = require('fs');
const path = require('path');
const { Parser } = require('json2csv');
const Handlebars = require('handlebars');

require('dotenv').config();

const domainsConfigPath = process.env.DOMAINS_CONFIG;

// ── Handlebars runtime options ────────────────────────────────────────────────
const runtimeOptions = {
    allowProtoPropertiesByDefault: true,
    allowProtoMethodsByDefault: true,
};

// ── File utilities ────────────────────────────────────────────────────────────

const readFileSafe = (filePath) => {
    try {
        return fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        console.error(`[!] Error leyendo archivo ${filePath}:`, err.message);
        return null;
    }
};

async function saveFileToUploadPath(id, filename, filecontent) {
    try {
        const uploadPath = process.env.UPLOAD_PATH;
        if (!uploadPath) throw new Error('UPLOAD_PATH is not defined in the .env file.');

        const folderPath = path.join(uploadPath, id.toString());
        if (!fs.existsSync(folderPath)) {
            fs.mkdirSync(folderPath, { recursive: true });
            console.log(`[5ELG] Folder created: ${folderPath}`);
        }

        const filePath = path.join(folderPath, filename);
        fs.writeFileSync(filePath, filecontent);
        console.log(`[5ELG] File saved successfully: ${filePath}`);
    } catch (error) {
        console.error('[5ELG] Error saving file:', error);
        throw error;
    }
}

const renderTemplate = (res, templatePath, data) => {
    const templateContent = fs.readFileSync(templatePath, 'utf8');
    const template = Handlebars.compile(templateContent, runtimeOptions);
    const renderedContent = template(data, runtimeOptions);
    res.send(renderedContent);
};

// ── CSV generation ────────────────────────────────────────────────────────────

async function generateCSV(logs) {
    try {
        if (!logs || logs.length === 0) throw new Error('No hay logs disponibles para generar el CSV.');
        const fields = ['Id','Ts','Dl','Ed','Er','html','screen','Ip','Ua','Fu','Fb','Fr','Jd'];
        const parser = new Parser({ fields });
        return parser.parse(logs);
    } catch (err) {
        console.error('[!] Error generando el CSV:', err.message);
        throw err;
    }
}

async function generateCSVIP(ipRecords) {
    try {
        if (!ipRecords || ipRecords.length === 0) throw new Error('No IP records available to generate the CSV.');
        const fields = ['ID','IP','MAC','DATA','GEO','SCAN','INTEL'];
        const parser = new Parser({ fields });
        return parser.parse(ipRecords);
    } catch (err) {
        console.error('[!] Error generating IP CSV:', err.message);
        throw err;
    }
}

// ── Dealer data processing ────────────────────────────────────────────────────

function processDealerData({ fpRequest, encodedScr, encodedPage, jsData, encodedReq, rts, ip, userAgent, fpUser, fpBrowser }) {
    const screenshotsDir = path.join(__dirname, '../Sources/screenshotsB64');
    if (!fs.existsSync(screenshotsDir)) fs.mkdirSync(screenshotsDir, { recursive: true });

    if (encodedScr)  fs.writeFileSync(path.join(screenshotsDir, `${fpRequest}.shot`), encodedScr, 'utf8');
    if (encodedPage) fs.writeFileSync(path.join(screenshotsDir, `${fpRequest}.code`), encodedPage, 'utf8');

    const newLog = {
        Dl:     '5ELG.DEALER',
        Ed:     jsData,
        Er:     encodedReq,
        Ts:     rts,
        Ip:     ip,
        Ua:     userAgent,
        Fu:     fpUser,
        Fb:     fpBrowser,
        Fr:     fpRequest,
        Jd:     jsData,
        Html:   encodedPage,
        Screen: encodedScr,
    };

    Log.create(newLog)
        .then(() => console.log('[5ELG-DEALER] Datos registrados:', { fpUser, rts }))
        .catch((err) => console.error('[DealerHandler] Error al guardar los datos:', err));
}

// ── Log management ────────────────────────────────────────────────────────────

async function handleBackupLogs() {
    try {
        const logs = await Log.findAll();
        if (!logs.length) throw new Error('No hay logs en la base de datos para respaldar.');

        const csv = await generateCSV(logs.map(log => log.toJSON()));

        const backupDir = process.env.BACKUP_PATH;
        if (!backupDir) throw new Error('La variable de entorno BACKUP_PATH no está definida.');

        const backupPath = path.join(backupDir, `backup_logs_${Date.now()}.csv`);
        fs.writeFileSync(backupPath, csv, 'utf8');
        console.log(`[5ELG] Backup generado con éxito en: ${backupPath}`);
        return backupPath;
    } catch (err) {
        console.error('[!] Error al realizar el backup:', err.message);
        throw err;
    }
}

async function generateCSVFingerprints(records) {
    try {
        if (!records || records.length === 0) throw new Error('No fingerprint records.');
        const fields = ['ID','FU','FB','IPS','NETDATA','INTEL','PWD'];
        const parser = new Parser({ fields });
        return parser.parse(records);
    } catch (err) {
        console.error('[!] Error generating fingerprints CSV:', err.message);
        throw err;
    }
}

async function handleFullBackup(res) {
    const backupDir = process.env.BACKUP_PATH;
    if (!backupDir) throw new Error('BACKUP_PATH not defined in .env');

    const ts = Date.now();

    // Fetch all tables concurrently
    const [logs, ips, fingers] = await Promise.all([
        Log.findAll().then(r => r.map(x => x.toJSON())).catch(() => []),
        IPINT.findAll().then(r => r.map(x => x.toJSON())).catch(() => []),
        FINGERDATA.findAll().then(r => r.map(x => x.toJSON())).catch(() => []),
    ]);

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename=5elg_full_backup_${ts}.zip`);

    const archive = archiver('zip', { zlib: { level: 6 } });
    archive.on('error', err => { throw err; });
    archive.pipe(res);

    if (logs.length) {
        const csvLogs = await generateCSV(logs).catch(() => null);
        if (csvLogs) archive.append(csvLogs, { name: `logs_${ts}.csv` });
    }
    if (ips.length) {
        const csvIPs = await generateCSVIP(ips).catch(() => null);
        if (csvIPs) archive.append(csvIPs, { name: `ipint_${ts}.csv` });
    }
    if (fingers.length) {
        const csvFP = await generateCSVFingerprints(fingers).catch(() => null);
        if (csvFP) archive.append(csvFP, { name: `fingerprints_${ts}.csv` });
    }

    await archive.finalize();
}

async function clearLogs(id = null) {
    try {
        if (id) {
            const deleted = await Log.destroy({ where: { id } });
            if (!deleted) throw new Error(`No se encontró un log con el ID ${id}`);
            console.log(`[5ELG] Log con ID ${id} eliminado con éxito.`);
            return `Log con ID ${id} eliminado con éxito.`;
        } else {
            const deletedCount = await Log.destroy({ where: {} });
            console.log(`[5ELG] Todos los logs han sido eliminados. (${deletedCount} registros eliminados)`);
            return 'Todos los logs han sido eliminados.';
        }
    } catch (err) {
        console.error('[!] Error al eliminar logs:', err.message);
        throw err;
    }
}

// ── Fingerprint records ───────────────────────────────────────────────────────

async function addFingerprintRecord(newData) {
    try {
        const existingRecord = await FINGERDATA.findOne({ where: { FU: newData.FU, FB: newData.FB } });
        if (existingRecord) return existingRecord;

        const newRecord = await FINGERDATA.create(newData);
        console.log(`[5ELG] New record added successfully with ID: ${newRecord.ID}`);
        return newRecord;
    } catch (error) {
        console.error('[5ELG] Error adding new record:', error);
        throw error;
    }
}

async function updateFingerprintRecordByFU(fu, updates, column) {
    try {
        const validColumns = ['IPS', 'NETDATA', 'INTEL', 'PWD'];
        if (!validColumns.includes(column)) {
            throw new Error(`[5ELG] Invalid column: ${column}. Valid columns are: ${validColumns.join(', ')}`);
        }

        const record = await FINGERDATA.findOne({ where: { FU: fu } });
        if (!record) {
            console.log(`[5ELG] No record found with FU: ${fu}`);
            return null;
        }

        const existingData = record[column] ? JSON.parse(record[column]) : [];
        const updatesArray = Array.isArray(updates) ? updates : [updates];
        const uniqueUpdates = updatesArray.filter(item =>
            typeof item === 'object'
                ? !existingData.some(e => JSON.stringify(e) === JSON.stringify(item))
                : !existingData.includes(item)
        );

        if (!uniqueUpdates.length) {
            console.log(`[5ELG] No new unique data to add for FU: ${fu} in column: ${column}`);
            return record;
        }

        await record.update({ [column]: existingData.concat(uniqueUpdates) });
        console.log(`[5ELG] Record with FU: ${fu} updated successfully in column: ${column}`);
        return record;
    } catch (error) {
        console.error('[5ELG] Error updating record by FU:', error);
        throw error;
    }
}

async function getAllFingerprintRecords() {
    try {
        const records = await FINGERDATA.findAll();
        if (!records.length) console.log('[5ELG] No records found in the database.');
        return records;
    } catch (error) {
        console.error('[5ELG] Error retrieving all records:', error);
        throw error;
    }
}

async function getFingerprintRecordByID(id) {
    try {
        const record = await FINGERDATA.findAll({ where: { FU: id } });
        if (!record) {
            console.log(`[5ELG] No record found with ID: ${id}`);
            return null;
        }
        return record;
    } catch (error) {
        console.error('[5ELG] Error retrieving record by ID:', error);
        throw error;
    }
}

// ── Domain config helpers (internal) ─────────────────────────────────────────

function readDomainsConfig() {
    try {
        const data = fs.readFileSync(domainsConfigPath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('[5ELG] Error leyendo domains config:', err.message);
        return { domains: [] };
    }
}

function writeDomainsConfig(json) {
    try {
        fs.writeFileSync(domainsConfigPath, JSON.stringify(json, null, 2), 'utf8');
    } catch (err) {
        console.error('[5ELG] Error escribiendo domains config:', err.message);
    }
}

// ── Domain CRUD ───────────────────────────────────────────────────────────────

function getDomains() {
    return readDomainsConfig().domains;
}

function addDomain(newDomain) {
    const json = readDomainsConfig();
    // ID auto-incremental robusto — usa el máximo existente en vez del último elemento
    // para que no se rompa si hay huecos por eliminaciones previas
    const maxId = json.domains.reduce((max, d) => Math.max(max, d.id ?? -1), -1);
    newDomain.id = maxId + 1;
    json.domains.push(newDomain);
    writeDomainsConfig(json);
}

function findDomainById(domainId) {
    return readDomainsConfig().domains.find(d => d.id === domainId) || null;
}

function activateDomain(domainId) {
    const json = readDomainsConfig();
    const domain = json.domains.find(d => d.id === domainId);
    if (domain) {
        domain.status = 'active';
        writeDomainsConfig(json);
    }
}

/**
 * Desactiva un dominio (status → inactive).
 */
function deactivateDomain(domainId) {
    const json = readDomainsConfig();
    const domain = json.domains.find(d => d.id === domainId);
    if (domain) {
        domain.status = 'inactive';
        writeDomainsConfig(json);
    }
}

/**
 * Elimina un dominio por ID.
 * @returns {boolean} true si se encontró y eliminó, false si no existía
 */
function removeDomain(domainId) {
    const json = readDomainsConfig();
    const before = json.domains.length;
    json.domains = json.domains.filter(d => d.id !== domainId);
    if (json.domains.length === before) return false;
    writeDomainsConfig(json);
    return true;
}

/**
 * Actualiza los campos de un dominio (merge parcial — nunca sobreescribe el id).
 * @returns {object|null} el dominio actualizado o null si no existe
 */
function updateDomain(domainId, updates) {
    const json = readDomainsConfig();
    const domain = json.domains.find(d => d.id === domainId);
    if (!domain) return null;

    const { id, ...safeUpdates } = updates;   // proteger el id
    Object.assign(domain, safeUpdates);

    if (domain.type) domain.type = domain.type.toUpperCase();

    writeDomainsConfig(json);
    return domain;
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
    // CSV
    generateCSV,
    generateCSVIP,
    generateCSVFingerprints,
    handleBackupLogs,
    handleFullBackup,
    // Files
    readFileSafe,
    saveFileToUploadPath,
    renderTemplate,
    // Logs
    clearLogs,
    processDealerData,
    // Fingerprints
    addFingerprintRecord,
    updateFingerprintRecordByFU,
    getAllFingerprintRecords,
    getFingerprintRecordByID,
    // Domains
    getDomains,
    addDomain,
    findDomainById,
    activateDomain,
    deactivateDomain,   //
    removeDomain,       //
    updateDomain,       //
};