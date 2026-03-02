# Vulnerable WebSocket Server - Educational Demo

> ⚠️ **WARNING: This server is INTENTIONALLY VULNERABLE** ⚠️

This code demonstrates the OpenClaw WebSocket localhost takeover vulnerability discovered by Oasis Security. It is designed for **EDUCATIONAL PURPOSES ONLY**.

## Purpose

This server mimics the vulnerable behavior of OpenClaw to help security professionals understand:

1. How WebSocket connections from browsers can reach localhost services
2. Why rate limiting must apply to localhost connections
3. Why device pairing should require explicit user confirmation

## Vulnerabilities Demonstrated

| Vulnerability | Description | Secure Alternative |
|--------------|-------------|-------------------|
| No rate limiting | Unlimited password attempts from localhost | Implement rate limiting for ALL sources |
| Auto-approve pairing | Device registration auto-approved from localhost | Require user confirmation via UI |
| No origin validation | WebSocket accepts any origin | Validate Origin header |

## Running the Server

```bash
# Default settings (port 9999, password "demo123")
go run main.go

# Custom settings
go run main.go -port 8888 -password "mypassword"
```

## WebSocket Protocol

### Connect

```
ws://localhost:9999/ws
```

### Authentication

```json
{"type": "auth", "payload": {"password": "demo123"}}
```

Response:
```json
{"type": "auth", "success": true, "data": {"sessionId": "session-xxx"}}
```

### Device Registration

```json
{"type": "register", "payload": {"deviceName": "Attacker Device"}}
```

### Commands

```json
{"type": "command", "payload": {"command": "search", "args": "API keys"}}
{"type": "getConfig"}
{"type": "getLogs"}
{"type": "getDevices"}
```

## Attack Flow

1. Victim visits malicious website
2. Website's JavaScript opens WebSocket to `localhost:9999`
3. JavaScript brute-forces password (no rate limiting)
4. JavaScript registers as trusted device (auto-approved)
5. JavaScript exfiltrates config, logs, and device list

## DO NOT

- Run this in production
- Expose this to untrusted networks
- Use this code as a template for real applications
- Deploy this anywhere outside of a controlled lab environment

## References

- [OpenClaw Vulnerability - Oasis Security](https://www.oasis.security/blog/openclaw-vulnerability)
- [Threat Model Spec](https://github.com/grokify/threat-model-spec)
