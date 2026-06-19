const express = require('express');
const router = express.Router();
const { Log, IPINT } = require('../Functions/db'); // Modelos Sequelize
const { Op } = require('../Functions/db'); // Base de datos
const sequelize = require('sequelize'); // Asegúrate de importar Sequelize correctamente

const { renderTemplate, processDealerData } = require('../Functions/utils');

const fs = require('fs');
const path = require('path');


// Define las funciones web dentro del objeto `webfuncs`
const webfuncs = {
    indexHandler: (req, res) => {
        const filePath = path.join(__dirname, '../Web/index.html'); // Ruta del archivo HTML

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('[!] Error al leer el archivo HTML:', err.message);
                res.status(500).send('ERROR'); // Respuesta con error 500
                return;
            }
    
            res.status(200).send(data); // Enviar el contenido del archivo HTML
        });
    },
    dashboard: async (req, res) => {
    try {
        const logs = await Log.findAll({
            attributes: [
                'Fb',
                'Fu',
                'Ip',
                'Ua',        // ← faltaba
                'Dl',
                'Er',
                'Ed',
                'ID',
                'Fr',
                'Jd',
                'html',
                'screen',
                // Ts del registro más reciente del grupo
                [sequelize.fn('MAX', sequelize.col('Ts')), 'Ts'],
            ],
            where: {
                Fu: { [Op.notIn]: ['', 'N/B'] },  // ← fix: filtra ambos valores
                Fb: { [Op.ne]: '' },
                Ip: { [Op.ne]: '' },
                Dl: { [Op.ne]: 'DNS.LOG' },
            },
            group: ['Fb', 'Fu', 'Ip', 'Ua', 'Dl', 'Er', 'Ed', 'ID', 'Fr', 'Jd', 'html', 'screen'],
            order: [[sequelize.fn('MAX', sequelize.col('Ts')), 'DESC']],
        });

        const safeJsonB = (v) => JSON.stringify(v || [])
            .replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
            .replace(/&/g, '\\u0026').replace(/'/g, '\\u0027');
        await renderTemplate(res, 'Web/browsers.html', {
            logs,
            logsJson: safeJsonB(logs),
        });
    } catch (err) {
        console.error('[5ELG] Error querying database:', err);
        res.status(500).send('Error loading dashboard.');
    }
},
    ippanel: async (req, res) => {
        try {
            // XSS-safe JSON: encodes <, >, &, ' as Unicode escapes so data
            // can never close a <script> tag or inject HTML, even in edge cases.
            const safeJson = (v) => JSON.stringify(v || [])
                .replace(/</g,  '\\u003c')
                .replace(/>/g,  '\\u003e')
                .replace(/&/g,  '\\u0026')
                .replace(/'/g,  '\\u0027');

            const [logsResult, ipsResult] = await Promise.allSettled([
                // Raw log entries (no GROUP BY) — last 10 000 records ordered by date.
                // Only the fields analyzeRAW() actually uses; Er/Jd can be large so keep them
                // but drop html/screen/Ed/Fr which are never read by the analysis.
                Log.findAll({
                    attributes: ['ID', 'Fu', 'Fb', 'Ip', 'Ua', 'Dl', 'Er', 'Jd', 'Ts'],
                    where: {
                        Ip: { [Op.ne]: '' },
                        Dl: { [Op.ne]: 'DNS.LOG' },
                    },
                    order: [['Ts', 'DESC']],
                    limit: 10000,
                }),
                IPINT.findAll({
                    attributes: ['ID', 'IP', 'DATA', 'GEO', 'SCAN', 'INTEL'],
                    order: [['ID', 'DESC']],
                }),
            ]);

            const logs = logsResult.status === 'fulfilled' ? logsResult.value : [];
            const ips  = ipsResult.status  === 'fulfilled' ? ipsResult.value  : [];

            if (logsResult.status === 'rejected')
                console.error('[5ELG] ippanel logs error:', logsResult.reason);
            if (ipsResult.status === 'rejected')
                console.error('[5ELG] ippanel ips error:', ipsResult.reason);

            // Bypass Handlebars — direct string replace is deterministic and
            // avoids any template-engine ambiguity with the large JSON payload.
            const template = fs.readFileSync(
                path.join(__dirname, '../Web/index.html'), 'utf8'
            );
            const html = template
                .replace('{{{logsJson}}}', safeJson(logs))
                .replace('{{{ipsJson}}}',  safeJson(ips));

            res.setHeader('Cache-Control', 'no-store');
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.send(html);
        } catch (err) {
            console.error('[5ELG] ippanel fatal:', err);
            res.status(500).send('Error loading index.');
        }
    },
   
    createLog: (req, res) => {
        // Código para crear un nuevo log
        res.send('Create log logic goes here.');
    },
    infoIP: async (req, res) => {
        try {
            if (!req.query.id) {
                return res.status(400).send('Error: Falta el parámetro "id".');
            }
            idreq = req.query.id;
            await renderTemplate(res, 'Web/infoIPX.html', { idreq }); //ASD

        } catch (error) {
            console.log(error);
            
        }
    },
    infoDeal: async (req, res) => {
        try {
            if (!req.query.id) {
                return res.status(400).send('Error: Falta el parámetro "id".');
            }

            const result = await Log.findAll({
                where: { Fr: { [Op.eq]: req.query.id } },
            });

            if (result.length === 0) {
                return res.status(404).send('Error: No se encontraron datos para el ID proporcionado.');
            }

            const record = result[0];


            // Try legacy files first, fall back to DB BLOB fields
            const screenshotDir = path.join(__dirname, '../Sources/screenshotsB64');
            const shotPath = path.join(screenshotDir, `${req.query.id}.shot`);
            const codePath = path.join(screenshotDir, `${req.query.id}.code`);


            let base64Shot = null;
            let base64Code = null;

            if (fs.existsSync(shotPath)) {
                base64Shot = fs.readFileSync(shotPath, 'utf8');

            } else if (record.screen) {
                try {
                    const raw = Buffer.from(record.screen).toString('utf8');
                    base64Shot = decodeURIComponent(raw);
                } catch (e) { /* silent */ }
            } else {
            }

            if (fs.existsSync(codePath)) {
                base64Code = fs.readFileSync(codePath, 'utf8');
            } else if (record.html) {
                base64Code = Buffer.from(record.html).toString('utf8');
            }

            // Decode the URL-encoded wrapper so the client gets clean base64
            let base64CodeClean = null;
            let base64ShotClean = null;
            if (base64Code) { try { base64CodeClean = decodeURIComponent(base64Code); } catch(_){ base64CodeClean = base64Code; } }
            if (base64Shot) { try { base64ShotClean = decodeURIComponent(base64Shot); } catch(_){ base64ShotClean = base64Shot; } }


            // Template uses {{#each result}} so pass result array; base64 accessed via {{@root.*}}
            await renderTemplate(res, 'Web/info.html', {
                result,
                base64Shot: base64ShotClean,
                base64Code: base64CodeClean,
            });

        } catch (err) {
            console.error('[5ELG] Error procesando la solicitud:', err.message);
            res.status(500).send('Error procesando la solicitud.');
        }
    },    
    scope: (req, res) => {
        const filePath = path.join(__dirname, '../Web/scope.html'); // Ruta del archivo HTML

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('[!] Error al leer el archivo HTML:', err.message);
                res.status(500).send('ERROR'); // Respuesta con error 500
                return;
            }
    
            res.status(200).send(data); // Enviar el contenido del archivo HTML
        });          
    },
    callback: (req, res) => {
        const filePath = path.join(__dirname, '../Web/callback.html'); // Ruta del archivo HTML

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('[!] Error al leer el archivo HTML:', err.message);
                res.status(500).send('ERROR'); // Respuesta con error 500
                return;
            }
    
            res.status(200).send(data); // Enviar el contenido del archivo HTML
        });        
    },
    dataDealer: (req, res) => {
        // Código para manejar "data-dealer"
        res.send('Data dealer handler logic goes here.');
    },
    dataLogs: (req, res) => {

        const filePath = path.join(__dirname, '../Web/statics.html'); // Ruta del archivo HTML

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('[!] Error al leer el archivo HTML:', err.message);
                res.status(500).send('ERROR'); // Respuesta con error 500
                return;
            }
    
            res.status(200).send(data); // Enviar el contenido del archivo HTML
        });  
    },
    runOldDealer: (req, res) => {
        const filePath = path.join(__dirname, '../Web/oldmerca.html'); // Ruta del archivo HTML

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('[!] Error al leer el archivo HTML:', err.message);
                res.status(500).send('ERROR'); // Respuesta con error 500
                return;
            }
    
            res.status(200).send(data); // Enviar el contenido del archivo HTML
        });  
    },
    dealerData: (req, res) => {
        //database.html
        const filePath = path.join(__dirname, '../Web/database.html'); // Ruta del archivo HTML

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('[!] Error al leer el archivo HTML:', err.message);
                res.status(500).send('ERROR'); // Respuesta con error 500
                return;
            }
    
            res.status(200).send(data); // Enviar el contenido del archivo HTML
        });  
    },
    filesRecAndData: (req, res) => {
        //database.html
        const filePath = path.join(__dirname, '../Web/files.html'); // Ruta del archivo HTML

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('[!] Error al leer el archivo HTML:', err.message);
                res.status(500).send('ERROR'); // Respuesta con error 500
                return;
            }
    
            res.status(200).send(data); // Enviar el contenido del archivo HTML
        });  
    },
    optionsData: (req, res) => {
        //database.html
        const filePath = path.join(__dirname, '../Web/options.html'); // Ruta del archivo HTML

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('[!] Error al leer el archivo HTML:', err.message);
                res.status(500).send('ERROR'); // Respuesta con error 500
                return;
            }
    
            res.status(200).send(data); // Enviar el contenido del archivo HTML
        });  
    },
    scannersData: (req, res) => {
        //database.html
        const filePath = path.join(__dirname, '../Web/scanners.html'); // Ruta del archivo HTML

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('[!] Error al leer el archivo HTML:', err.message);
                res.status(500).send('ERROR'); // Respuesta con error 500
                return;
            }
    
            res.status(200).send(data); // Enviar el contenido del archivo HTML
        });  
    },
};


router.use('/dashboard', webfuncs.dashboard); 
router.use('/info', webfuncs.infoDeal); 
router.use('/ipdata', webfuncs.infoIP); 

router.use('/callback', webfuncs.callback); 
router.use('/dealers', webfuncs.dealerData); 
router.use('/scanners', webfuncs.scannersData); 
router.use('/files', webfuncs.filesRecAndData); 
router.use('/options', webfuncs.optionsData); 

router.use('/statics', webfuncs.dataLogs); 
router.use('/upload', webfuncs.scope); //FILE UPLOAD

router.use('/logs', webfuncs.createLog); 
//INTERNAL DEALER EXEMPLE
router.use('/index', webfuncs.ippanel); 

// Exportar el router para que pueda ser utilizado en el servidor principal
module.exports = router;
