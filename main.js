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

// Banner para el servidor
console.log(`${C.Yellow}.------. .------. .------. .------.${C.Reset}`);
console.log(`${C.Yellow}|0.--. | |F.--. | |C.--. | |4.--. |${C.Reset}`);
console.log(`${C.Yellow}| (  ) | | (\\/) | | :/\\: | | :/\\: |${C.Reset}`);
console.log(`${C.Yellow}|(_||_)| |  \\/  | | (__) | | :\\/: |${C.Reset}`);
console.log(`${C.Yellow}| '--'0| | '--'F| | '--'C| | '--'4|${C.Reset}`);
console.log(`${C.Yellow}'------' '------' '------' '------'${C.Reset}`);
console.log(`${C.Bold}[5ELG] Brow5er dEal finGerprinter. FINGERPRINT & OSINT WEB PANEL${C.Reset}`);
console.log(`${C.Dim}[5ELG] See more at https://github.com/jomoza/5ELG${C.Reset}`);
console.log(`${C.Dim}_________________________________________________${C.Reset}`);


const args = process.argv.slice(2);

if (['-help', '--help', '-h', '-?'].some(flag => args.includes(flag))) {
    console.log(`
Usage: node main.js [options]

Options:
  -help          Show this help message and exit
  -ssl           Enable SSL for the HTTP service
  -dns           Start the DNS server
  -icmp          Start the ICMP listener
  -host <host>   Specify the host (default: localhost)
  -port <port>   Specify the port (default: 80)
  -domain <domain> Specify the domain (default: localhost)
  -iface <interface> Specify the network interface (default: lo)

Environment Variables:
  INTERFACE          Network interface to use (default: lo)
  HOST               Host to bind the services (default: localhost)
  DOMAIN             Domain name
  VELG_USER          User for authentication
  VELG_PWD           Password for authentication
  ICMP_LISTENER      Enable ICMP listener (true/false)
  SHODAN_API_KEY     API key for Shodan
  INFODB_KEY         API key for InfoDB
  CRIMINALIP_API_KEY API key for CriminalIP

Examples:
  node main.js -ssl -dns -host 127.0.0.1 -port 8080
  node main.js -icmp -iface eth0
    `);
    process.exit(0);
}

//SERVICES
const path = require('path');
const fs = require('fs');
const { startDnsServer } = require('./Functions/servers/dns'); 
const { startIcmpListener } = require('./Functions/servers/icmp'); 
const { runHTTPService } = require('./Functions/servers/https'); 

const { Log, IPINT, sequelize, Op } = require('./Functions/db');
const { getDomains } = require('./Functions/utils');
const { listUsers } = require('./Functions/auth');

require('dotenv').config(); // ENV


const requiredVars = [
    'INTERFACE',
    'HOST',
    'DOMAIN',
    'VELG_USER',
    'VELG_PWD',
    'SHODAN_API_KEY',
    'SSL_KEY_PATH',
    'SSL_CERT_PATH',
    'INFODB_KEY',
    'CRIMINALIP_API_KEY'
];


function checkEnvVars() {
    const keysToCensor = ['VELG_PWD', 'SHODAN_API_KEY', 'VIRUSTOTAL_KEY', 'INFODB_KEY', 'CRIMINALIP_API_KEY'];
    const keysToSkip = ['HOST', 'DOMAIN'];

    requiredVars.forEach((varName) => {
        if (keysToSkip.includes(varName)) return;

        const varValue = process.env[varName];
        let displayValue = varValue;

        if (keysToCensor.includes(varName) && varValue) {
            displayValue = `${C.Dim}${varValue.substring(0, 4)}***${C.Reset}`;
        }

        console.log(`${C.Magenta}[5ELG-CONFIG]${C.Reset} ${C.Cyan}.env:${varName}${C.Reset} => ${displayValue || `${C.Dim}Not Set${C.Reset}`}`);
    });

    const configsPath = path.join(__dirname, 'Sources', 'data', 'configs.json');
    if (fs.existsSync(configsPath)) {
        try {
            const configs = JSON.parse(fs.readFileSync(configsPath, 'utf8'));
            Object.keys(configs).forEach(key => {
                if (key === 'dealerdomains') return;
                console.log(`${C.Magenta}[5ELG-CONFIG]${C.Reset} ${C.Cyan}configs.json:${key.toUpperCase()}${C.Reset} => ${C.White}${JSON.stringify(configs[key])}${C.Reset}`);
            });
        } catch (err) {
            console.error(`${C.Red}[5ELG-CONFIG] Error reading configs.json:${C.Reset}`, err.message);
        }
    }
}

function checkDealers() {
    const dealersPath = path.join(__dirname, 'Sources', 'data', 'dealers.json');
    if (fs.existsSync(dealersPath)) {
        try {
            const dealersConfig = JSON.parse(fs.readFileSync(dealersPath, 'utf8'));
            // Handle both {"domains": [...]} and [...]
            const dealersList = dealersConfig.domains || (Array.isArray(dealersConfig) ? dealersConfig : []);
            
            const activeDealers = dealersList.filter(d => d.status === 'active');
            
            if (dealersList.length > 0) {
                console.log(`${C.Green}[5ELG-DEALERS]${C.Reset} Found ${C.Bold}${dealersList.length}${C.Reset} dealers, ${C.Bold}${activeDealers.length}${C.Reset} are active.`);
                activeDealers.forEach(dealer => {
                    let info = `  - ${C.Red}${dealer.name}${C.Reset} ${C.Dim}(Type: ${dealer.type || 'N/A'})${C.Reset}`;
                    if (dealer.isproxy) {
                        info += ` ${C.Yellow}[PROXY]${C.Reset}`;
                    }
                    if (dealer.redirect) {
                        info += ` -> ${C.Cyan}${dealer.redirect}${C.Reset}`;
                    }
                    console.log(info);
                });
            } else {
                console.log(`${C.Green}[5ELG-DEALERS]${C.Reset} ${C.Dim}No dealers found in dealers.json.${C.Reset}`);
            }
        } catch (err) {
            console.error(`${C.Red}[5ELG-DEALERS] Error parsing dealers.json:${C.Reset}`, err.message);
        }
    } else {
        console.log(`${C.Green}[5ELG-DEALERS]${C.Reset} ${C.Dim}dealers.json not found. No dealers loaded.${C.Reset}`);
    }
}

function checkUsers() {
    try {
        const users = listUsers();
        if (!users.length) {
            console.log(`${C.Yellow}[5ELG-USERS]${C.Reset} ${C.Dim}No users found in users.json.${C.Reset}`);
            return;
        }
        console.log(`${C.Yellow}[5ELG-USERS]${C.Reset} ${C.Bold}${users.length}${C.Reset} registered user${users.length !== 1 ? 's' : ''}:`);
        users.forEach(u => {
            const roleColor = u.role === 'admin' ? C.Red : C.Cyan;
            const lastLogin = u.lastLogin ? u.lastLogin.toString().slice(0, 19).replace('T', ' ') : 'never';
            console.log(`  - ${C.White}${u.username}${C.Reset} ${roleColor}[${u.role || 'user'}]${C.Reset} ${C.Dim}last login: ${lastLogin}${C.Reset}`);
        });
    } catch (err) {
        console.error(`${C.Red}[5ELG-USERS] Error reading users:${C.Reset}`, err.message);
    }
}

const isSSL = args.includes('-ssl');

const useDNS = args.includes('-dns');
const useICMP = args.includes('-icmp');

// Determinar host y puerto desde argumentos de línea de comandos, variables de entorno o valores por defecto
const argHostIndex = args.indexOf('-host');
const argPortIndex = args.indexOf('-port');
const argDomainIndex = args.indexOf('-domain');
const argIface = args.indexOf('-iface');


const HOST = argHostIndex !== -1 ? args[argHostIndex + 1] : process.env.HOST || 'localhost';
const PORT = argPortIndex !== -1 ? args[argPortIndex + 1] : process.env.PORT || 80;
const SSL_PORT = argPortIndex !== -1 ? args[argPortIndex + 1] : process.env.SSL_PORT || 443; // Puerto para HTTPS
const DOMAIN = argDomainIndex !== -1 ? args[argDomainIndex + 1] : process.env.DOMAIN || 'localhost'; // Dominio por defecto
const IFACE = argIface !== -1 ? args[argIface + 1] : process.env.INTERFACE || 'lo'; // Dominio por defecto


(async () => {
    checkEnvVars();

    //RUN HTTP SERVICE TO RUN DASHBOARD, API, 
    await runHTTPService(isSSL, HOST, PORT, SSL_PORT, DOMAIN);
    
    try {
        // Enable WAL (Write-Ahead Logging) mode for SQLite to improve concurrency.
        await sequelize.query('PRAGMA journal_mode=WAL;');
        // Set a busy timeout to make SQLite wait if the database is locked, further reducing contention issues.
        await sequelize.query('PRAGMA busy_timeout = 5000;'); // 5 seconds timeout
        console.log(`${C.Green}[5ELG-DB]${C.Reset} WAL mode enabled & busy_timeout set to 5000ms to reduce lock contention.`);
        await sequelize.sync({ force: false, alter: false });
        console.log(`${C.Green}[5ELG-DB]${C.Reset} Todas las tablas están sincronizadas.`);
    } catch (err) {
        console.error(`${C.Red}[5ELG-DB] Error al sincronizar la base de datos:${C.Reset}`, err);
    }

    checkDealers();
    checkUsers();

    // Check if DNS ICMP SMTP (TODO) services should be started
    if( useDNS || process.env["DNS_SERVER"].toLowerCase() == "true" ) {
        startDnsServer(HOST,DOMAIN,53);                
        const domains = getDomains();
        if (domains && domains.length > 0) {
            const totalDomains = domains.length;
            const activeDomains = domains.filter(d => d.status === 'active').length;

            console.log(`${C.Green}[5ELG-DOMAIN]${C.Reset} Found ${C.Bold}${totalDomains}${C.Reset} domain configurations (${C.Bold}${activeDomains} active).`);

            // Agrupar por dominio raíz para encontrar el más poblado
            const domainGroups = {};
            domains.forEach(domain => {
                const parts = domain.name.split('.');
                const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : domain.name;
                domainGroups[rootDomain] = (domainGroups[rootDomain] || 0) + 1;
            });

            const mostPopulated = Object.entries(domainGroups).reduce((max, current) => current[1] > max[1] ? current : max, ['', 0]);

            if (mostPopulated[1] > 5) { // Umbral para considerar "muchos" registros
                console.log(`  - ${C.Dim}: '${C.Reset}${C.Cyan}${mostPopulated[0]}${C.Dim}' has ${C.Reset}${C.Bold}${mostPopulated[1]}${C.Dim} records.${C.Reset}`);
            }
        } else {
            console.log(`${C.Green}[5ELG-DOMAIN]${C.Reset} ${C.Dim}No domains configured.${C.Reset}`);
        }

        process.env["DNS_SERVER"] = "true";

    }

    if( useICMP || process.env["ICMP_LISTENER"].toLowerCase() == "true" ) {
        console.log(`${C.Green}[5ELG-SERVICES]${C.Reset} ICMP LISTENER is running at ${C.Cyan}icmp://${HOST}${C.Reset}`);
        (async () => {
            try {
                await startIcmpListener(IFACE);
                process.env["ICMP_LISTENER"] = "true";
            } catch (err) {
                console.error('[ICMP-SERVER] Failed to start:', err);
            }
        })();

    }


})();
