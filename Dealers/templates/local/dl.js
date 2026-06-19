
/* ── SHA-256 (pure JS, no external deps) ── */
function sha256(str) {
    const K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    let h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const utf8 = unescape(encodeURIComponent(str));
    const bytes = new Uint8Array(utf8.length);
    for (let i = 0; i < utf8.length; i++) bytes[i] = utf8.charCodeAt(i);
    const bitLen = bytes.length * 8;
    let padLen = bytes.length + 1;
    while (padLen % 64 !== 56) padLen++;
    padLen += 8;
    const buf = new Uint8Array(padLen);
    buf.set(bytes);
    buf[bytes.length] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(padLen - 4, bitLen >>> 0, false);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let i = 0; i < padLen; i += 64) {
        const w = new Uint32Array(64);
        for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, false);
        for (let j = 16; j < 64; j++) {
            const s0 = rotr(w[j-15],7)  ^ rotr(w[j-15],18) ^ (w[j-15]>>>3);
            const s1 = rotr(w[j-2], 17) ^ rotr(w[j-2], 19) ^ (w[j-2] >>>10);
            w[j] = (w[j-16] + s0 + w[j-7] + s1) >>> 0;
        }
        let [a,b,c,d,e,f,g,hh] = h;
        for (let j = 0; j < 64; j++) {
            const S1  = rotr(e,6)  ^ rotr(e,11)  ^ rotr(e,25);
            const ch  = (e & f)   ^ (~e & g);
            const t1  = (hh + S1 + ch + K[j] + w[j]) >>> 0;
            const S0  = rotr(a,2)  ^ rotr(a,13)  ^ rotr(a,22);
            const maj = (a & b)   ^ (a & c)   ^ (b & c);
            const t2  = (S0 + maj) >>> 0;
            hh=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
        }
        h[0]=(h[0]+a)>>>0; h[1]=(h[1]+b)>>>0; h[2]=(h[2]+c)>>>0; h[3]=(h[3]+d)>>>0;
        h[4]=(h[4]+e)>>>0; h[5]=(h[5]+f)>>>0; h[6]=(h[6]+g)>>>0; h[7]=(h[7]+hh)>>>0;
    }
    return h.map(x => x.toString(16).padStart(8,'0')).join('');
}

let dealerUri = "555ELGCODETAG-1";
let encodedPageHTML;
let encodedImg;
let fingerprint;

function getGpuModel() {
    let canvas = document.createElement("canvas");
    let gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    return gl ? gl.getParameter(gl.RENDERER) : "WebGL not supported";
}

function objToString(obj) {
    return Object.entries(obj).reduce((str, [key, val]) => `${str}${key}::${val}\n`, '');
}

// Collect extensive browser and device data for fingerprinting, including experimental APIs
function getFingerprintDataExtended() {
    let data = {};

    // Browser plugins
    data.browserPlugins = [...navigator.plugins].map(p => `${p.name} ${p.version}`).join(";");

    // Device data
    let deviceData = {};
    ["hardwareConcurrency", "maxTouchPoints", "platform", "product", "vendor", "languages", "deviceMemory"].forEach(key => {
        deviceData[key] = navigator[key] || null;
    });

    // GPU information
    data.gpuData = {
        colorDepth: screen.colorDepth,
        renderer: getGpuModel()
    };

    // Browser data
    let browserData = {};
    ["appCodeName", "appName", "appVersion", "language", "product", "productSub", "userAgent", "onLine"].forEach(key => {
        browserData[key] = navigator[key] || null;
    });
    browserData.actualUri = location.href;

    // Collect permission statuses
    let permissions = {};
    ["geolocation", "accelerometer", "camera", "clipboard-read", "clipboard-write", "microphone", "notifications", "persistent-storage", "payment-handler", "midi"].forEach(permission => {
        navigator.permissions.query({ name: permission }).then(status => {
            permissions[permission] = status.state;
        }).catch(err => console.warn(`Permission query failed for ${permission}:`, err));
    });
    browserData.permissions = objToString(permissions);

    // Battery data
    if (navigator.getBattery) {
        navigator.getBattery().then(battery => {
            browserData.batteryData = {
                charging: battery.charging,
                chargingTime: battery.chargingTime,
                dischargingTime: battery.dischargingTime,
                level: battery.level
            };
        }).catch(err => console.warn('Failed to access battery data:', err));
    }

    // Media devices
    if (navigator.mediaDevices) {
        navigator.mediaDevices.enumerateDevices().then(devices => {
            browserData.mediaDevices = devices.map(d => `${d.kind}: ${d.label}`).join("; ");
        }).catch(err => console.warn('Failed to access media devices:', err));
    }

    // WebRTC IP leaks (getting local IP via WebRTC)
    try {
        let rtcPeerConnection = new RTCPeerConnection({ iceServers: [] });
        rtcPeerConnection.createDataChannel(''); // Create an empty data channel
        rtcPeerConnection.createOffer()
            .then(offer => rtcPeerConnection.setLocalDescription(offer))
            .catch(err => console.warn('Error creating offer:', err));

        rtcPeerConnection.onicecandidate = function (ice) {
            // Ensure the candidate is not null and has valid information
            if (ice.candidate && ice.candidate.candidate) {
                const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
                browserData.rtcdata = ice.candidate.candidate;
                const localIP = ice.candidate.candidate.match(ipRegex);
                if (localIP) {
                    browserData.localIP = localIP[1]; // Store the extracted IP address
                    console.log('Local IP detected:', localIP[1]);
                }
            } else {
                console.log('ICE gathering completed or no valid candidate found.');
            }
        };
    } catch (err) {
        console.warn('Failed to access WebRTC IP:', err);
    }


    // Network Information API (Experimental)
    try {
        if (navigator.connection) {
            browserData.networkInfo = {
                downlink: navigator.connection.downlink,
                effectiveType: navigator.connection.effectiveType,
                rtt: navigator.connection.rtt,
                saveData: navigator.connection.saveData
            };
        }
    } catch (err) {
        console.warn('Failed to access network information:', err);
    }

    // Device Orientation and Motion (Experimental)
    try {
        window.addEventListener("deviceorientation", function (event) {
            browserData.deviceOrientation = {
                alpha: event.alpha,
                beta: event.beta,
                gamma: event.gamma
            };
        }, true);

        window.addEventListener("devicemotion", function (event) {
            browserData.deviceMotion = {
                acceleration: event.acceleration,
                accelerationIncludingGravity: event.accelerationIncludingGravity,
                rotationRate: event.rotationRate,
                interval: event.interval
            };
        }, true);
    } catch (err) {
        console.warn('Failed to access device orientation/motion:', err);
    }

    // Memory API (Experimental)
    try {
        if (performance && performance.memory) {
            browserData.memoryInfo = {
                jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
                totalJSHeapSize: performance.memory.totalJSHeapSize,
                usedJSHeapSize: performance.memory.usedJSHeapSize
            };
        }
    } catch (err) {
        console.warn('Failed to access memory information:', err);
    }

    // Touch Capabilities (Experimental)
    try {
        browserData.touchCapabilities = {
            maxTouchPoints: navigator.maxTouchPoints,
            touchEventSupported: 'ontouchstart' in window,
            pointerEventSupported: 'onpointerdown' in window
        };
    } catch (err) {
        console.warn('Failed to access touch capabilities:', err);
    }

    data.deviceData = deviceData;
    data.browserData = browserData;
    return data;
}

function generateBrowserFingerprint() {
    const fingerprintData = {
        cookieEnabled: navigator.cookieEnabled,
        font: getComputedStyle(document.documentElement).fontSize,
        primaryLanguage: navigator.language || navigator.userLanguage || navigator.browserLanguage,
        timezone: new Date().getTimezoneOffset() / -60,
        screenResolution: `${screen.width}x${screen.height}`
    };
    return sha256(JSON.stringify(fingerprintData));
}

window.onload = function() {
    try {
        const data = getFingerprintDataExtended();
        const userFingerprint = generateBrowserFingerprint();
        const fingerprintData = sha256(JSON.stringify(data));
        const pageHTML = document.documentElement.outerHTML;
        encodedPageHTML = btoa(encodeURIComponent(pageHTML));

        const payload = new URLSearchParams({
            u:    userFingerprint,
            b:    fingerprintData,
            r:    sha256(JSON.stringify(data)),
            code: encodeURIComponent(encodedPageHTML),
            data: btoa(JSON.stringify(data))
        });

        const xhr = new XMLHttpRequest();
        xhr.open("POST", dealerUri, true);
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        xhr.onreadystatechange = function() {
            if (this.readyState === XMLHttpRequest.DONE && this.status === 200) {
                console.log("Data sent successfully!");
            }
        };
        xhr.send(payload.toString());

    } catch (error) {
        console.error("Error during fingerprinting:", error);
    }
};

