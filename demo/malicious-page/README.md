# Malicious Attack Page - Educational Demo

> ⚠️ **WARNING: This page demonstrates an actual attack technique** ⚠️

This HTML page simulates a malicious website that exploits the OpenClaw WebSocket localhost takeover vulnerability.

## How It Works

1. **User visits this "innocent" page** — it looks like a normal website
2. **JavaScript connects to localhost** — browsers allow WebSocket to localhost
3. **Brute-force authentication** — no rate limiting means instant password cracking
4. **Auto-register as device** — localhost connections are auto-approved
5. **Exfiltrate data** — config, logs, API keys, device list extracted

## Running the Demo

### Step 1: Start the vulnerable server

```bash
cd ../vulnerable-server
go run main.go
```

### Step 2: Serve this page

```bash
# Using Python
python3 -m http.server 8080

# Using Node.js
npx serve .

# Using Go
go run -mod=mod golang.org/x/tools/cmd/present@latest
```

### Step 3: Open in browser

Navigate to `http://localhost:8080` and click "Start Attack Demo"

## What You'll See

1. WebSocket connection established to localhost:9999
2. Password brute-force (tries common passwords)
3. Successful authentication (password: demo123)
4. Device registration (auto-approved)
5. Data exfiltration:
   - API keys (OpenAI, AWS, GitHub, Slack)
   - Configuration files
   - Application logs
   - Connected device list

## Key Security Lessons

### Why This Works

| Browser Behavior | Security Implication |
|-----------------|---------------------|
| WebSocket to localhost allowed | Any website can connect to local services |
| No preflight for WebSocket | CORS doesn't protect WebSocket |
| Same-origin doesn't apply | localhost:9999 ≠ attacker.com but connection allowed |

### How to Prevent

1. **Rate limit ALL connections** — including localhost
2. **Require user confirmation** — for device pairing
3. **Validate Origin header** — reject unexpected origins
4. **Use Unix sockets** — instead of TCP for local IPC
5. **Cryptographic tokens** — instead of passwords

## Files

- `index.html` — The attack page (self-contained, no dependencies)
- `README.md` — This documentation

## DO NOT

- Host this on a public server
- Use this against systems you don't own
- Remove the educational warnings
