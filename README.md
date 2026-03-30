# Privacy Messenger

Messenger that routes all traffic through the Tor network using `.onion` hidden services.

## Dependency

```bash
pip install cryptography pysocks
```

## How to Run

### 1. generate TLS certificate

```bash
openssl req -x509 -newkey rsa:2048 -keyout private_key.pem -out certificate.pem -days 365 -nodes -subj "/CN=localhost"
```

### 2. run tor with with the default SOCKS proxy on `127.0.0.1:9050`

```bash
tor
```

### 3. find your .onion address

```bash
cat /opt/homebrew/var/lib/tor/hidden_service/hostname
```

### 4. start the server

```bash
python3 server.py
```

### 5. run client on any computer

```bash
python3 client.py <your alias> <server .onion address>
```

