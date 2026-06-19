FROM node:22-bookworm-slim

# System deps:
#   nmap        → scanner
#   libpcap-dev → compile pcap (ICMP listener)
#   libpcap0.8  → runtime pcap
#   python3 / make / g++ → compile native Node addons (sqlite3, raw-socket, pcap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpcap-dev \
    libpcap0.8 \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies before copying the rest (better cache layer)
COPY package*.json ./
RUN npm install

# Copy application source
COPY . .

# Ensure persistent directories exist inside the image
# (actual data comes from bind-mounts at runtime)
RUN mkdir -p \
    Sources/data \
    Sources/files \
    Sources/backups \
    Sources/screenshotsB64

EXPOSE 80 443 53/tcp 53/udp

CMD ["node", "main.js"]
