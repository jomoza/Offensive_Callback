const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const https = require('https');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');   
const path = require('path');
const { Log, IPINT, sequelize } = require('../../Functions/db');
const { runWebSocketServer } = require('./wss.js');
const { authMiddleware } = require('../../Functions/auth');
const dealerRoutes    = require('../../Proyect/dealer');
const webRoutes       = require('../../Proyect/web');
const webPublicRoutes = require('../../Proyect/web-public');
const apiRoutes       = require('../../Proyect/api');
const uploadRoutes    = require('../../Proyect/files');

// ANSI escape codes for colors and styles
const C = {
    Reset: "\x1b[0m",
    Bold: "\x1b[1m",
    Dim: "\x1b[2m",
    Red: "\x1b[31m",
    Green: "\x1b[32m",
    Yellow: "\x1b[33m",
    Cyan: "\x1b[36m",
    Magenta: "\x1b[35m",
    White: "\x1b[37m",
};




async function runHTTPService(isSSL, HOST, PORT, SSL_PORT, DOMAIN) {
    
    let webservice;
    
    const app = express();
    app.use(bodyParser.json({ limit: '500mb' }));
    app.use(bodyParser.urlencoded({ limit: '500mb', extended: true }));
    app.use(express.json()); 
    app.use(express.urlencoded({ extended: true })); 
    app.use(cors()); 
    app.use((req, res, next) => {
        res.setHeader('Content-Security-Policy', "default-src 'self' http: https: data: blob: ws: 'unsafe-inline' 'unsafe-eval';");
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        next();
    });

    app.use('/web/assets', express.static('Web/assets')); 
    

    app.use('/upload', uploadRoutes); 
    // /dealer SIN autenticación básica
    app.use('/dealer', dealerRoutes);
    app.use('/run', webPublicRoutes);


    app.use('/web', authMiddleware, webRoutes);
    app.use('/api', authMiddleware, apiRoutes);

    // Cualquier otra ruta no definida arriba pasa directamente por el dealer (sin redirección ni autenticación)
    app.use('/', dealerRoutes);

    const printStartupInfo = () => {
        const protocol = isSSL ? 'https' : 'http';
        const activePort = isSSL ? SSL_PORT : PORT;
        const line = `${C.Green}-------------------------------------------------------------------------${C.Reset}`;

        console.log(line);
        console.log(`${C.Bold}[5ELG-DASHBOARD]${C.Reset} Access 5ELG via ${C.Yellow}==> ${protocol}://${DOMAIN}:${activePort}/web/index${C.Reset}`);
        console.log(line);

        const dealerUris = new Set();
        // From .env
        if (DOMAIN && DOMAIN !== 'localhost') {
            dealerUris.add(DOMAIN);
        }

        // From configs.json
        const configsPath = path.join(__dirname, '../../Sources/data/configs.json');
        if (fs.existsSync(configsPath)) {
            try {
                const configs = JSON.parse(fs.readFileSync(configsPath, 'utf8'));
                if (configs && Array.isArray(configs.dealerdomains)) {
                    configs.dealerdomains.forEach(d => dealerUris.add(d));
                }
            } catch (e) {
                console.warn(`${C.Yellow}[5ELG] Could not parse configs.json for dealer domains.${C.Reset}`);
            }
        }

        if (dealerUris.size > 0) {
            console.log(`${C.Bold}[5ELG-DEALER URIS] Available domains:${C.Reset}`);
            dealerUris.forEach(uri => console.log(`  - ${C.Cyan}${protocol}://${uri}/dealer${C.Reset}`));
        }
        console.log(line);
        console.log(`${C.Bold}[5ELG-DEALER URIS]${C.Reset} Test dealer available at ${C.Bold}${C.Yellow}==> ${protocol}://${DOMAIN}:${activePort}/run/deal${C.Reset}`);
        console.log(line);
    
    };

    if (isSSL) {
        if (process.env.SSL_KEY_PATH && process.env.SSL_CERT_PATH) {
            try {
                const privateKey = fs.readFileSync(process.env.SSL_KEY_PATH, 'utf8');
                const certificate = fs.readFileSync(process.env.SSL_CERT_PATH, 'utf8');
                const credentials = { key: privateKey, cert: certificate };

                // Iniciar servidor HTTPS con todas las funcionalidades
                webservice = https.createServer(credentials, app).listen(SSL_PORT, HOST, async () => {
                    console.log(`${C.Green}[5ELG-SERVICE]${C.Reset} HTTPS server running at ${C.Cyan}https://${HOST}:${SSL_PORT}${C.Reset}`);
                    printStartupInfo();
                    
                    try {
                        await sequelize.authenticate(); // Verificar conexión con la base de datos
                        console.log(`${C.Green}[5ELG-DB]${C.Reset} Database connected successfully.`);
                    } catch (err) {
                        console.error(`${C.Red}[5ELG-DB] Database connection failed:${C.Reset}`, err);
                    }
                });

                // Iniciar un servidor HTTP secundario solo para el dealer
                const httpDealerApp = express();
                httpDealerApp.use(bodyParser.json({ limit: '500mb' }));
                httpDealerApp.use(bodyParser.urlencoded({ limit: '500mb', extended: true }));
                httpDealerApp.use(cors());
                httpDealerApp.use('/', dealerRoutes); // Solo rutas de dealer

                http.createServer(httpDealerApp).listen(PORT, HOST, () => {
                    console.log(`${C.Green}[5ELG-SERVICE]${C.Reset} HTTP server (dealer-only) running at ${C.Cyan}http://${HOST}:${PORT}${C.Reset}`);
                });

            } catch (err) {
                console.error(`${C.Red}[5ELG] Failed to load SSL certificates:${C.Reset}`, err);
                process.exit(1); // Salir si no se pueden cargar los certificados
            }
        } else {
            console.error(`${C.Red}[5ELG] SSL_KEY_PATH and SSL_CERT_PATH must be set in the .env file for HTTPS.${C.Reset}`);
            process.exit(1); // Salir si las rutas de los certificados no están configuradas
        }
    } else {
        // Iniciar servidor HTTP con todas las funcionalidades
        webservice = http.createServer(app).listen(PORT, HOST, async () => {
            console.log(`${C.Green}[5ELG-SERVICE]${C.Reset} HTTP server running at ${C.Cyan}http://${HOST}:${PORT}${C.Reset}`);
            printStartupInfo();

            try {
                await sequelize.authenticate(); // Verificar conexión con la base de datos
                console.log(`${C.Green}[5ELG-DB]${C.Reset} Database connected successfully.`);
            } catch (err) {
                console.error(`${C.Red}[5ELG-DB] Database connection failed:${C.Reset}`, err);
            }
        });
    }
    // El servidor WebSocket se adjunta al servidor principal (HTTPS si está activo, si no, HTTP)
    if (webservice) runWebSocketServer(webservice);
}

module.exports = { runHTTPService }