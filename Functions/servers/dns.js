/**
 * 5ELG DNS Server Handler (dns.js)
 *
 * - Responde a consultas DNS para dominios configurados dinámicamente según un archivo JSON (ruta en .env: DOMAINS_CONFIG).
 * - Permite definir múltiples dominios, su IP/valor, tipo de registro (A, AAAA, TXT, etc.) y estado (activo/inactivo).
 * - Si el dominio está inactivo, siempre responde con localhost.
 * - Si el dominio no está en la config → fallback según .env:
 *     DNS_RELAY=true  + DNS_RELAY_IP=1.1.1.1  → reenvía la query al relay (resolver externo)
 *     DNS_RELAY=false                           → responde con HOST= del .env
 * - Todas las solicitudes se registran en la base de datos para telemetría.
 *
 * Autor: 5ELG
 */

const dns    = require('native-dns');
const dgram  = require('dgram');           // usado para relay UDP
const crypto = require('crypto');
const { Log } = require('../../Functions/db');

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


/* ─── helpers de entorno ──────────────────────────────────────────── */

const RELAY_ENABLED = (process.env.DNS_RELAY || '').toLowerCase() === 'true';
const RELAY_IP      = (process.env.DNS_RELAY_IP || '1.1.1.1').trim();
const SELF_IP       = (process.env.HOST || '127.0.0.1').trim();

/**
 * Reenvía la pregunta DNS raw al relay y devuelve la respuesta parseada.
 * Usa UDP nativo para evitar dependencias adicionales.
 * @param {Buffer} rawPacket  - Paquete DNS completo tal como llegó
 * @param {string} relayIp    - IP del resolver externo
 * @param {number} relayPort  - Puerto (defecto 53)
 * @returns {Promise<Buffer>} - Buffer de respuesta del relay
 */
function relayQuery(rawPacket, relayIp, relayPort = 53) {
    return new Promise((resolve, reject) => {
        const client = dgram.createSocket('udp4');
        const timeout = setTimeout(() => {
            client.close();
            reject(new Error('DNS relay timeout'));
        }, 3000);

        client.once('message', (msg) => {
            clearTimeout(timeout);
            client.close();
            resolve(msg);
        });
        client.once('error', (err) => {
            clearTimeout(timeout);
            client.close();
            reject(err);
        });

        client.send(rawPacket, relayPort, relayIp);
    });
}

/**
 * Parsea una respuesta DNS raw y extrae los answers para añadirlos
 * a la respuesta nativa-dns en curso.
 * native-dns no expone un parser completo de respuestas, así que
 * delegamos en el módulo `dns` propio de Node para tipos básicos.
 */
function skipDnsName(buf, offset) {
    // Skip an RFC 1035 encoded name (handles inline labels and compression pointers)
    while (offset < buf.length) {
        const len = buf[offset];
        if (len === 0) { offset += 1; break; }           // root label
        if ((len & 0xC0) === 0xC0) { offset += 2; break; } // compression pointer — always 2 bytes
        offset += 1 + len;                               // inline label
    }
    return offset;
}

function parseRelayAnswers(relayBuf) {
    // Extraemos answers manualmente del buffer binario (RFC 1035)
    // Sólo A y AAAA — el resto se ignora
    const answers = [];
    try {
        const ancount = relayBuf.readUInt16BE(6);
        if (ancount === 0) return answers;

        // Skip header (12 bytes) + question section
        let offset = 12;
        const qdcount = relayBuf.readUInt16BE(4);
        for (let i = 0; i < qdcount; i++) {
            offset = skipDnsName(relayBuf, offset);
            offset += 4; // qtype (2) + qclass (2)
        }

        for (let i = 0; i < ancount; i++) {
            if (offset + 10 > relayBuf.length) break; // safety: need at least name(2) + fixed fields(10)
            offset = skipDnsName(relayBuf, offset);
            if (offset + 10 > relayBuf.length) break;

            const rtype = relayBuf.readUInt16BE(offset);     offset += 2;
            /* rclass */                                       offset += 2;
            const ttl   = relayBuf.readUInt32BE(offset);     offset += 4;
            const rdlen = relayBuf.readUInt16BE(offset);     offset += 2;

            if (offset + rdlen > relayBuf.length) break; // truncated
            const rdata = relayBuf.slice(offset, offset + rdlen);
            offset += rdlen;

            if (rtype === 1 && rdlen === 4) {
                // A record — always valid IPv4
                const addr = Array.from(rdata).join('.');
                answers.push({ type: 'A', address: addr, ttl });
            } else if (rtype === 28 && rdlen === 16) {
                // AAAA — zero-pad each group to 4 hex chars so ipaddr.js can parse it
                const parts = [];
                for (let b = 0; b < 16; b += 2) {
                    parts.push(rdata.readUInt16BE(b).toString(16).padStart(4, '0'));
                }
                answers.push({ type: 'AAAA', address: parts.join(':'), ttl });
            }
            // Other types (CNAME, HTTPS, etc.) are intentionally skipped
        }
    } catch (e) {
        console.warn(`${C.Yellow}[5ELG-DNS-RELAY] Error parsing relay response:${C.Reset}`, e.message);
    }
    return answers;
}

/* ─── logging ────────────────────────────────────────────────────── */

async function logRequest(info, dID) {
    const encodedReq  = Buffer.from(JSON.stringify(info.requestData)).toString('base64');
    const encodedData = Buffer.from(JSON.stringify(info.clientData)).toString('base64');
    const hashReq     = crypto.createHash('sha256').update(JSON.stringify(info)).digest('hex');
    const hashFng     = info.fingerprint || 'N/B';
    const hashbro     = crypto.createHash('sha256').update(hashFng).digest('hex');

    try {
        await Log.create({
            Dl:     dID,
            Ed:     encodedData,
            Er:     encodedReq,
            Ts:     info.timestamp,
            Ip:     info.clientIp,
            Ua:     info.username || 'N/A',
            Fu:     hashFng,
            Fb:     hashbro,
            Fr:     hashReq,
            Jd:     encodedData,
            Html:   null,
            Screen: null,
        });
        console.log(`${C.Green}[5ELG-DNS-LOG]${C.Reset} Log registrado: ${C.Bold}${info.domain}${C.Reset}`);
    } catch (error) {
        console.error(`${C.Red}[5ELG-DNS-LOG] Error al registrar log:${C.Reset}`, error.message);
    }
}

/* ─── resolución desde config JSON ──────────────────────────────── */

function resolveDomainFromConfig(domainName, recordType) {
    const fs = require('fs');
    const configPath = process.env.DOMAINS_CONFIG;
    if (!configPath) throw new Error('DOMAINS_CONFIG not set in .env');

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const domain = config.domains.find(d => d.name === domainName);

    if (!domain) return null;                  // no en config → fallback externo
    if (domain.record !== recordType) return null;

    if (domain.status !== 'active') {
        // Dominio inactivo → localhost
        if (recordType === 'A')    return '127.0.0.1';
        if (recordType === 'AAAA') return '::1';
        return 'localhost';
    }

    return domain.ip;
}

/* ─── servidor ───────────────────────────────────────────────────── */

function startDnsServer(Dnshost, domainToRegister, dnsPort) {
    const server = dns.createServer();

    server.on('request', async (request, response) => {

        const clientIp   = request.address.address || 'N/A';
        const clientPort = request.address.port    || 'N/A';
        const question   = request.question[0]     || {};
        const domain     = question.name           || 'N/A';
        const timestamp  = new Date().toISOString();

        /* fingerprint / dealerID */
        let fingerprint = 'N/A';
        let dealerID    = 'DNS.LOG';
        const domainParts = domain.split('.');
        const dealerIdx   = domainParts.findIndex(p => p.toLowerCase() === 'dealer5elg');
        if (dealerIdx > 0) {
            const prev1 = domainParts[dealerIdx - 1] || '';
            const prev2 = dealerIdx - 2 >= 0 ? domainParts[dealerIdx - 2] : '';
            fingerprint = prev2 + prev1;
            dealerID    = 'DNS.REQUEST';
        } else {
            fingerprint = domain.replace(`.${domainToRegister}`, '') || 'N/A';
        }

        /* requestData */
        const requestData = {
            counts: {
                qdcount: request.qdcount,
                ancount: request.ancount,
                nscount: request.nscount,
                arcount: request.arcount,
            },
            questions:   request.question.map(q  => ({ name: q.name,   type: dns.consts.QTYPE_TO_NAME[q.type]   || 'UNKNOWN', class: dns.consts.QCLASS_TO_NAME[q.class] || 'UNKNOWN' })),
            answers:     request.answer.map(a    => ({ name: a.name,   type: dns.consts.QTYPE_TO_NAME[a.type]   || 'UNKNOWN', class: dns.consts.QCLASS_TO_NAME[a.class] || 'UNKNOWN', ttl: a.ttl, data: a.data })),
            authorities: request.authority.map(a => ({ name: a.name,   type: dns.consts.QTYPE_TO_NAME[a.type]   || 'UNKNOWN', class: dns.consts.QCLASS_TO_NAME[a.class] || 'UNKNOWN', ttl: a.ttl, data: a.data })),
            additionals: request.additional.map(a=> ({ name: a.name,   type: dns.consts.QTYPE_TO_NAME[a.type]   || 'UNKNOWN', class: dns.consts.QCLASS_TO_NAME[a.class] || 'UNKNOWN', ttl: a.ttl, data: a.data })),
            dealer_uri:  'N/A',
            merca_uri:   domain,
            requestURL:  'DNS',
            method:      dns.consts.QTYPE_TO_NAME[question.type] || 'UNKNOWN',
        };

        /* clientData */
        const clientData = {
            header: {
                id:     request.header.id,
                qr:     request.header.qr,
                opcode: request.header.opcode,
                aa:     request.header.aa,
                tc:     request.header.tc,
                rd:     request.header.rd,
                ra:     request.header.ra,
                res1:   request.header.res1 || 0,
                res2:   request.header.res2 || 0,
                res3:   request.header.res3 || 0,
                rcode:  dns.consts.RCODE_TO_NAME[request.header.rcode] || 'UNKNOWN',
            },
            edns: {
                version:     request.edns ? request.edns.version     : 'N/A',
                options:     request.edns ? request.edns.options      : [],
                payloadSize: request.edns ? request.edns.payloadSize  : 'N/A',
            },
        };

        /* log async (no bloquea la respuesta) */
        logRequest({ clientIp, timestamp, clientPort, domain, fingerprint, clientData, requestData }, dealerID);

        /* ── resolver cada pregunta ── */
        for (const q of request.question) {
            const qName = q.name.replace(/\u0000+$/, '');
            const qType = dns.consts.QTYPE_TO_NAME[q.type] || 'UNKNOWN';

            console.log(`${C.Green}[5ELG-DNS]${C.Reset} Domain: ${C.Bold}${qName}${C.Reset}  Type: ${C.Cyan}${qType}${C.Reset}`);

            /* 1. Intentar config local */
            let localAnswer;
            try { localAnswer = resolveDomainFromConfig(qName, qType); }
            catch (e) { localAnswer = null; }

            if (localAnswer !== null) {
                /* Tenemos respuesta propia */
                console.log(`${C.Green}[5ELG-DNS-RESPONSE]${C.Reset} Local → ${C.Bold}${qName}${C.Reset} (${qType}) = ${C.Cyan}${JSON.stringify(localAnswer)}${C.Reset}`);
                pushAnswer(response, qName, qType, localAnswer);
                continue;
            }

            /* 2. No está en config → fallback */
            if (RELAY_ENABLED) {
                /* ── RELAY: reenviar al resolver externo ── */
                console.log(`${C.Yellow}[5ELG-DNS-RELAY]${C.Reset} No local record for ${C.Bold}${qName}${C.Reset} (${qType}) — relaying to ${C.Cyan}${RELAY_IP}${C.Reset}`);
                try {
                    const relayBuf  = await relayQuery(request.rawPacket, RELAY_IP);
                    const relayAnss = parseRelayAnswers(relayBuf);

                    if (relayAnss.length > 0) {
                        for (const ans of relayAnss) {
                            console.log(`${C.Yellow}[5ELG-DNS-RELAY]${C.Reset} Got ${ans.type} = ${C.Cyan}${ans.address}${C.Reset}`);
                            if (ans.type === 'A') {
                                response.answer.push(dns.A({ name: qName, address: ans.address, ttl: ans.ttl || 300 }));
                            } else if (ans.type === 'AAAA') {
                                response.answer.push(dns.AAAA({ name: qName, address: ans.address, ttl: ans.ttl || 300 }));
                            }
                        }
                    } else {
                        /* Relay no devolvió nada útil → HOST */
                        console.log(`${C.Yellow}[5ELG-DNS-RELAY]${C.Reset} ${C.Dim}Empty relay response for ${qName} — falling back to HOST (${SELF_IP})${C.Reset}`);
                        pushFallbackHost(response, qName, qType);
                    }
                } catch (relayErr) {
                    /* Relay falló → HOST */
                    console.error(`${C.Red}[5ELG-DNS-RELAY] Relay error for ${qName}: ${relayErr.message} — falling back to HOST (${SELF_IP})${C.Reset}`);
                    pushFallbackHost(response, qName, qType);
                }
            } else {
                /* ── NO RELAY: responder con HOST del .env ── */
                console.log(`${C.Green}[5ELG-DNS-RESPONSE]${C.Reset} ${C.Dim}No local record, relay disabled — responding with HOST (${SELF_IP}) for ${qName} (${qType})${C.Reset}`);
                pushFallbackHost(response, qName, qType);
            }
        }

        try { response.send(); }
        catch (sendErr) { console.error(`${C.Red}[5ELG-DNS-SEND] Failed to send response for ${domain}: ${sendErr.message}${C.Reset}`); }
    });

    server.on('error',       (err) => console.error(`${C.Red}[5ELG-DNS-ERROR] ${err}${C.Reset}`));
    server.on('socketError', (err) => console.error(`${C.Red}[5ELG-DNS-SOCKET-ERROR] ${err}${C.Reset}`));
    server.on('listening',   ()    => {
        
        console.log(`${C.Green}[5ELG-DNS]${C.Reset} Server is running at ${C.Cyan}dns://${Dnshost}:53${C.Reset}`);
        console.log(`${C.Green}[5ELG-DNS-SERVER]${C.Reset} Nameserver: ${C.Bold}${domainToRegister}${C.Reset}`);
        console.log(`${C.Green}[5ELG-DNS-SERVER]${C.Reset} Relay: ${RELAY_ENABLED ? `${C.Bold}enabled${C.Reset} → ${C.Cyan}${RELAY_IP}${C.Reset}` : `${C.Dim}disabled${C.Reset} → HOST=${C.Cyan}${SELF_IP}${C.Reset}`}`);
    });
    server.on('close', () => console.log(`${C.Dim}[5ELG-DNS-SERVER] Server closed${C.Reset}`));

    server.serve(dnsPort, Dnshost);
}

/* ─── helpers de respuesta ───────────────────────────────────────── */

/**
 * Añade una respuesta local (desde config JSON) al objeto response.
 */
function pushAnswer(response, qName, qType, answer) {
    switch (qType) {
        case 'A':
            response.answer.push(dns.A({ name: qName, address: answer, ttl: 600 }));
            break;
        case 'AAAA':
            response.answer.push(dns.AAAA({ name: qName, address: answer, ttl: 600 }));
            break;
        case 'CNAME':
            response.answer.push(dns.CNAME({ name: qName, data: answer, ttl: 600 }));
            break;
        case 'MX':
            if (typeof answer === 'object' && answer.exchange) {
                response.answer.push(dns.MX({ name: qName, exchange: answer.exchange, priority: answer.priority || 10, ttl: 600 }));
            } else {
                response.answer.push(dns.MX({ name: qName, exchange: answer, priority: 10, ttl: 600 }));
            }
            break;
        case 'NS':
            response.answer.push(dns.NS({ name: qName, data: answer, ttl: 600 }));
            break;
        case 'PTR':
            response.answer.push(dns.PTR({ name: qName, data: answer, ttl: 600 }));
            break;
        case 'SOA':
            if (typeof answer === 'object' && answer.nsname) {
                response.answer.push(dns.SOA({ name: qName, ttl: 600, nsname: answer.nsname, hostmaster: answer.hostmaster, serial: answer.serial || 20250718, refresh: answer.refresh || 3600, retry: answer.retry || 600, expire: answer.expire || 604800, minimum: answer.minimum || 86400 }));
            } else {
                response.answer.push(dns.SOA({ name: qName, ttl: 600, nsname: 'ns1.localhost', hostmaster: 'hostmaster.localhost', serial: 20250718, refresh: 3600, retry: 600, expire: 604800, minimum: 86400 }));
            }
            break;
        case 'SRV':
            if (typeof answer === 'object' && answer.target) {
                response.answer.push(dns.SRV({ name: qName, ttl: 600, priority: answer.priority || 10, weight: answer.weight || 5, port: answer.port, target: answer.target }));
            }
            break;
        case 'TXT':
            response.answer.push(dns.TXT({ name: qName, data: Array.isArray(answer) ? answer : [answer], ttl: 600 }));
            break;
        default:
            response.answer.push(dns.A({ name: qName, address: answer, ttl: 600 }));
    }
}

/**
 * Responde con la IP propia del servidor (HOST del .env) cuando
 * no hay registro local y el relay está deshabilitado (o falló).
 */
function pushFallbackHost(response, qName, qType) {
    switch (qType) {
        case 'A':
            response.answer.push(dns.A({ name: qName, address: SELF_IP, ttl: 60 }));
            break;
        case 'AAAA':
            // HOST es IPv4; no podemos responder AAAA con él directamente
            // Devolvemos NXDOMAIN implícito (sin añadir respuesta)
            break;
        case 'TXT':
            response.answer.push(dns.TXT({ name: qName, data: [SELF_IP], ttl: 60 }));
            break;
        default:
            // Para el resto de tipos que no tienen respuesta → no añadimos nada (NXDOMAIN)
            break;
    }
}

module.exports = { startDnsServer };