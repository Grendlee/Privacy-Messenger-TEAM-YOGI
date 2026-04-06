# Privacy Messenger

Messenger that routes all traffic through the Tor network using `.onion` hidden services.

## Dependency

```bash
pip install cryptography pysocks
```

## How to Run

### 1. run Tor

**Option A — standalone Tor daemon (SOCKS on port 9050)**
```bash
tor
```

**Option B — Tor Browser (SOCKS on port 9150)**

Just open Tor Browser and leave it running.

### 2. find your .onion address (server machine only)

```bash
cat /opt/homebrew/var/lib/tor/hidden_service/hostname
```

> This path may differ depending on how/where you installed Tor.

### 3. start the server

TLS certificate and key are generated automatically on first run.

```bash
python3 server.py
```

### 4. run client on any computer

**Using standalone Tor (port 9050, default):**
```bash
python3 client.py <your alias> <server .onion address>
```

**Using Tor Browser (port 9150):**

macOS/Linux:
```bash
SOCKS_PORT=9150 python3 client.py <your alias> <server .onion address>
```

Windows (PowerShell):
```powershell
$env:SOCKS_PORT = "9150"
python client.py <your alias> <server .onion address>
```

## Running Tests

```bash
python3 tests.py
```

Tests spin up their own server instance automatically — no need to start the server manually.
