#!/bin/bash
# Record Attack Demo with Video
#
# This script records the full attack demonstration using screen capture.
# It launches the automated demo and captures video of the browser.
#
# Requirements:
# - ffmpeg (for screen recording)
# - Go 1.24+
# - Vibium clicker (npm install -g vibium)
#
# Usage:
#   ./record-demo.sh
#   ./record-demo.sh --no-video  # Screenshots only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
VIDEO_FILE="${OUTPUT_DIR}/attack-demo-$(date +%Y%m%d-%H%M%S).mp4"
RECORD_VIDEO=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-video)
            RECORD_VIDEO=false
            shift
            ;;
        *)
            shift
            ;;
    esac
done

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                      ║"
echo "║   🎬 ATTACK DEMO VIDEO RECORDER                                     ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Check dependencies
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ Required dependency not found: $1"
        echo "   Please install it and try again."
        exit 1
    fi
}

check_dependency "go"

if [ "$RECORD_VIDEO" = true ]; then
    if ! command -v ffmpeg &> /dev/null; then
        echo "⚠️  ffmpeg not found - will capture screenshots only"
        RECORD_VIDEO=false
    fi
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."

    # Stop ffmpeg if running
    if [ -n "$FFMPEG_PID" ]; then
        kill "$FFMPEG_PID" 2>/dev/null || true
        wait "$FFMPEG_PID" 2>/dev/null || true
    fi

    # Kill any leftover processes
    pkill -f "vulnerable-server" 2>/dev/null || true

    echo "✅ Cleanup complete"
}
trap cleanup EXIT

# Start screen recording (macOS)
if [ "$RECORD_VIDEO" = true ]; then
    echo "🎥 Starting screen recording..."

    # Get screen dimensions for macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS screen recording with ffmpeg
        # Capture the main display
        ffmpeg -f avfoundation -framerate 30 -i "1:none" \
            -vcodec libx264 -preset ultrafast -crf 23 \
            -pix_fmt yuv420p \
            "${VIDEO_FILE}" \
            -y 2>/dev/null &
        FFMPEG_PID=$!
        echo "   Recording to: ${VIDEO_FILE}"
        sleep 2
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux screen recording with ffmpeg
        DISPLAY_SIZE=$(xdpyinfo | grep dimensions | awk '{print $2}')
        ffmpeg -f x11grab -framerate 30 -video_size "${DISPLAY_SIZE}" -i :0.0 \
            -vcodec libx264 -preset ultrafast -crf 23 \
            -pix_fmt yuv420p \
            "${VIDEO_FILE}" \
            -y 2>/dev/null &
        FFMPEG_PID=$!
        echo "   Recording to: ${VIDEO_FILE}"
        sleep 2
    else
        echo "⚠️  Screen recording not supported on this OS"
        RECORD_VIDEO=false
    fi
fi

# Run the automated demo
echo ""
echo "🚀 Starting automated attack demo..."
echo ""

cd "${SCRIPT_DIR}"
go run main.go -output "${OUTPUT_DIR}" -headless=false -wait 20s

# Stop recording
if [ "$RECORD_VIDEO" = true ] && [ -n "$FFMPEG_PID" ]; then
    echo ""
    echo "🛑 Stopping screen recording..."
    kill -INT "$FFMPEG_PID" 2>/dev/null || true
    wait "$FFMPEG_PID" 2>/dev/null || true

    if [ -f "${VIDEO_FILE}" ]; then
        VIDEO_SIZE=$(du -h "${VIDEO_FILE}" | cut -f1)
        echo "✅ Video saved: ${VIDEO_FILE} (${VIDEO_SIZE})"
    fi
fi

# Summary
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "                         DEMO COMPLETE"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "📁 Output directory: ${OUTPUT_DIR}"
echo ""
echo "📸 Screenshots:"
ls -la "${OUTPUT_DIR}"/*.png 2>/dev/null || echo "   (none)"
echo ""
if [ "$RECORD_VIDEO" = true ] && [ -f "${VIDEO_FILE}" ]; then
    echo "🎥 Video: ${VIDEO_FILE}"
fi
echo ""
echo "To view screenshots:"
echo "   open ${OUTPUT_DIR}"
echo ""
