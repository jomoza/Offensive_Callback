const { NmapScan } = require('node-nmap'); // Paquete node-nmap
const { IPINT } = require('../db'); // Modelo Sequelize

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

function safeParse(raw) {
    if (!raw) return {};
    let parsed = raw;
    // Parsear repetidamente para evitar el problema de strings doblemente codificados que dejó código viejo
    while (typeof parsed === 'string') {
        try { parsed = JSON.parse(parsed); } 
        catch (e) { break; }
    }
    return (typeof parsed === 'object' && parsed !== null) ? parsed : {};
}

function scanAndUpdateWithNmap(ip) {
    return new Promise((resolve, reject) => {
        try {
            console.log(`${C.Magenta}[5ELG-NMAP]${C.Reset} Iniciando escaneo NMAP para IP: ${C.Bold}${ip}${C.Reset}`);

            const nmapScan = new NmapScan(ip, '-sV -F');

            // Escucha el evento "complete" para procesar los resultados del escaneo
            nmapScan.on('complete', async (nmapResults) => {
                try {
                    console.log(`${C.Magenta}[5ELG-NMAP]${C.Reset} Escaneo NMAP completado para IP: ${C.Bold}${ip}${C.Reset}`);

                    // Buscar el registro de la IP
                    const ipRecord = await IPINT.findOne({ where: { IP: ip } });
                    if (!ipRecord) {
                        console.error(`${C.Red}[5ELG-NMAP] No record found for IP: ${ip}${C.Reset}`);
                        return resolve(null);
                    }

                    // Parsear los datos existentes de forma segura
                    let existingData = safeParse(ipRecord.DATA);

                    // Fusionar datos existentes con los nuevos resultados
                    const insertData = {
                        ...existingData,
                        nmap: nmapResults
                    };

                    // Actualizar el registro pasando un Objeto directo (NO stringify)
                    await IPINT.update({ DATA: insertData }, { where: { IP: ip } });

                    console.log(`${C.Magenta}[5ELG-NMAP]${C.Reset} Updated DATA in database for IP: ${C.Bold}${ip}${C.Reset}`);
                    resolve(nmapResults);
                } catch (error) {
                    console.error(`${C.Red}[5ELG-NMAP] Error al actualizar los datos de NMAP para la IP: ${ip}${C.Reset}`, error);
                    reject(error);
                }
            });

            // Escucha el evento "error" para manejar errores durante el escaneo
            nmapScan.on('error', (error) => {
                console.error(`${C.Red}[5ELG-NMAP] Error durante el escaneo NMAP para la IP: ${ip}${C.Reset}`, error);
                reject(error);
            });

            // Iniciar el escaneo de Nmap
            nmapScan.startScan();
        } catch (error) {
            console.error(`${C.Red}[5ELG-NMAP] Error al iniciar el escaneo NMAP para la IP: ${ip}${C.Reset}`, error);
            reject(error);
        }
    });
}

module.exports = { scanAndUpdateWithNmap };
