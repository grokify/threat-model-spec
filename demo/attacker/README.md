# Automated Attack Demo with Video Capture

This directory contains automation to run and record the OpenClaw vulnerability demonstration.

## Overview

The automation:

1. Starts the vulnerable WebSocket server
2. Serves the malicious attack page
3. Launches a browser (via Vibium)
4. Navigates to the attack page
5. Clicks "Start Attack Demo"
6. Captures screenshots at key moments
7. Optionally records video of the entire process

## Requirements

- Go 1.24+
- Vibium clicker: `npm install -g vibium`
- ffmpeg (optional, for video recording)

## Quick Start

### Screenshots Only

```bash
go run main.go
```

### With Video Recording

```bash
./record-demo.sh
```

### Options

```bash
# Show browser window (default)
go run main.go -headless=false

# Run headless (for CI)
go run main.go -headless=true

# Custom output directory
go run main.go -output ./my-output

# Longer wait time for slower systems
go run main.go -wait 30s

# All options
go run main.go -server-port 9999 -page-port 8080 -headless=false -output ./output -wait 20s
```

## Output

The automation produces:

```
output/
├── 01-initial-page.png           # Attack page before starting
├── 02-attack-started.png         # WebSocket connecting
├── 03-brute-force.png            # Password brute-force in progress
├── 04-authenticated.png          # Authentication successful
├── 05-exfiltrating.png           # Data exfiltration
├── 06-attack-complete.png        # Attack finished
├── 07-final-exfiltrated-data.png # Full page with results
├── 08-exfiltrated-data-detail.png # Zoomed on stolen data
└── attack-demo-YYYYMMDD-HHMMSS.mp4  # Video (if recorded)
```

## What the Demo Shows

| Screenshot | Description |
|------------|-------------|
| 01 | The "innocent" attack page before the attack |
| 02-03 | WebSocket connection and brute-force in progress |
| 04 | Successful authentication (no rate limiting!) |
| 05 | Device auto-registered, data being exfiltrated |
| 06-08 | Attack complete with all stolen data displayed |

## Troubleshooting

### "Failed to launch browser"

Make sure Vibium is installed:
```bash
npm install -g vibium
```

### "Failed to start server"

The vulnerable server might already be running. Kill it:
```bash
pkill -f "vulnerable-server"
```

### Video not recording

Install ffmpeg:
```bash
# macOS
brew install ffmpeg

# Linux
sudo apt install ffmpeg
```

## Security Notice

This automation is for **EDUCATIONAL PURPOSES ONLY**. It demonstrates real security vulnerabilities to help developers understand attack patterns.

## Files

- `main.go` — Go automation using Vibium
- `record-demo.sh` — Shell script with video recording
- `README.md` — This documentation
