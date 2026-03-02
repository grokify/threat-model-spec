// Automated Attack Demo with Video Capture
//
// This program orchestrates the full OpenClaw vulnerability demonstration:
// 1. Starts the vulnerable WebSocket server
// 2. Serves the malicious attack page
// 3. Launches a browser and navigates to the attack page
// 4. Executes the attack and captures screenshots/video
//
// Usage:
//
//	go run main.go
//	go run main.go -headless=false  # Show browser window
//	go run main.go -record          # Enable screen recording (if available)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	vibium "github.com/plexusone/vibium-go"
)

// Config holds the automation configuration
type Config struct {
	VulnerableServerPort int
	AttackPagePort       int
	Headless             bool
	Record               bool
	OutputDir            string
	WaitTime             time.Duration
}

func main() {
	config := Config{}
	flag.IntVar(&config.VulnerableServerPort, "server-port", 9999, "Vulnerable server port")
	flag.IntVar(&config.AttackPagePort, "page-port", 8080, "Attack page server port")
	flag.BoolVar(&config.Headless, "headless", false, "Run browser in headless mode")
	flag.BoolVar(&config.Record, "record", false, "Enable screen recording")
	flag.StringVar(&config.OutputDir, "output", "output", "Output directory for screenshots/video")
	flag.DurationVar(&config.WaitTime, "wait", 15*time.Second, "Time to wait for attack to complete")
	flag.Parse()

	// Create output directory
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	fmt.Print(`
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   🎬 AUTOMATED ATTACK DEMO - VIDEO CAPTURE                          ║
║                                                                      ║
║   This will demonstrate the OpenClaw WebSocket vulnerability        ║
║   and capture screenshots/video of the attack.                       ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n⚠️  Interrupt received, cleaning up...")
		cancel()
	}()

	// Run the demo
	if err := runDemo(ctx, config); err != nil {
		log.Fatalf("Demo failed: %v", err)
	}
}

func runDemo(ctx context.Context, config Config) error {
	// Step 1: Start vulnerable server
	fmt.Println("\n📡 Step 1: Starting vulnerable WebSocket server...")
	serverCmd, err := startVulnerableServer(ctx, config.VulnerableServerPort)
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer func() {
		if serverCmd.Process != nil {
			_ = serverCmd.Process.Kill()
		}
	}()
	time.Sleep(2 * time.Second) // Wait for server to start

	// Step 2: Start attack page server
	fmt.Println("🌐 Step 2: Starting attack page server...")
	pageServer, err := startAttackPageServer(config.AttackPagePort)
	if err != nil {
		return fmt.Errorf("failed to start page server: %w", err)
	}
	defer func() { _ = pageServer.Close() }()
	time.Sleep(1 * time.Second)

	// Step 3: Launch browser
	fmt.Println("🌐 Step 3: Launching browser...")
	var vibe *vibium.Vibe
	var launchErr error

	if config.Headless {
		vibe, launchErr = vibium.LaunchHeadless(ctx)
	} else {
		vibe, launchErr = vibium.Launch(ctx)
	}
	if launchErr != nil {
		return fmt.Errorf("failed to launch browser: %w", launchErr)
	}
	defer func() { _ = vibe.Quit(ctx) }()

	// Step 4: Navigate to attack page
	attackURL := fmt.Sprintf("http://localhost:%d", config.AttackPagePort)
	fmt.Printf("📍 Step 4: Navigating to %s...\n", attackURL)
	if err := vibe.Go(ctx, attackURL); err != nil {
		return fmt.Errorf("failed to navigate: %w", err)
	}
	time.Sleep(2 * time.Second)

	// Take initial screenshot
	fmt.Println("📸 Taking initial screenshot...")
	if err := takeScreenshot(ctx, vibe, config.OutputDir, "01-initial-page.png"); err != nil {
		log.Printf("Warning: screenshot failed: %v", err)
	}

	// Step 5: Click "Start Attack Demo" button
	fmt.Println("🖱️  Step 5: Clicking 'Start Attack Demo' button...")
	startButton, err := vibe.Find(ctx, "#startButton", nil)
	if err != nil {
		return fmt.Errorf("failed to find start button: %w", err)
	}
	if err := startButton.Click(ctx, nil); err != nil {
		return fmt.Errorf("failed to click button: %w", err)
	}

	// Step 6: Wait and capture progress
	fmt.Println("⏳ Step 6: Waiting for attack to complete...")

	// Take screenshots at intervals
	screenshotTimes := []struct {
		delay time.Duration
		name  string
	}{
		{2 * time.Second, "02-attack-started.png"},
		{4 * time.Second, "03-brute-force.png"},
		{6 * time.Second, "04-authenticated.png"},
		{8 * time.Second, "05-exfiltrating.png"},
		{10 * time.Second, "06-attack-complete.png"},
	}

	for _, st := range screenshotTimes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(st.delay):
			fmt.Printf("📸 Taking screenshot: %s\n", st.name)
			if err := takeScreenshot(ctx, vibe, config.OutputDir, st.name); err != nil {
				log.Printf("Warning: screenshot failed: %v", err)
			}
		}
	}

	// Wait for any remaining time
	remaining := config.WaitTime - 10*time.Second
	if remaining > 0 {
		time.Sleep(remaining)
	}

	// Final screenshot showing exfiltrated data
	fmt.Println("📸 Taking final screenshot with exfiltrated data...")
	if err := takeScreenshot(ctx, vibe, config.OutputDir, "07-final-exfiltrated-data.png"); err != nil {
		log.Printf("Warning: screenshot failed: %v", err)
	}

	// Scroll to show exfiltrated data section
	fmt.Println("📜 Scrolling to exfiltrated data section...")
	_, err = vibe.Evaluate(ctx, "document.getElementById('exfilSection').scrollIntoView({behavior: 'smooth'})")
	if err != nil {
		log.Printf("Warning: scroll failed: %v", err)
	}
	time.Sleep(1 * time.Second)

	if err := takeScreenshot(ctx, vibe, config.OutputDir, "08-exfiltrated-data-detail.png"); err != nil {
		log.Printf("Warning: screenshot failed: %v", err)
	}

	fmt.Println("\n✅ Demo complete!")
	fmt.Printf("📁 Screenshots saved to: %s\n", config.OutputDir)

	// List output files
	files, _ := filepath.Glob(filepath.Join(config.OutputDir, "*.png"))
	fmt.Println("\n📸 Captured screenshots:")
	for _, f := range files {
		fmt.Printf("   - %s\n", filepath.Base(f))
	}

	return nil
}

func startVulnerableServer(ctx context.Context, port int) (*exec.Cmd, error) {
	// Get the path to the vulnerable server
	serverDir := filepath.Join(filepath.Dir(os.Args[0]), "..", "vulnerable-server")

	// Check if we're in the right directory structure
	if _, err := os.Stat(filepath.Join(serverDir, "main.go")); err != nil {
		// Try from current working directory
		cwd, _ := os.Getwd()
		serverDir = filepath.Join(cwd, "..", "vulnerable-server")
		if _, err := os.Stat(filepath.Join(serverDir, "main.go")); err != nil {
			// Try absolute path
			serverDir = filepath.Join(os.Getenv("HOME"), "go/src/github.com/grokify/threat-model-spec/demo/vulnerable-server")
		}
	}

	cmd := exec.CommandContext(ctx, "go", "run", "main.go",
		"-port", fmt.Sprintf("%d", port),
		"-password", "demo123")
	cmd.Dir = serverDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return cmd, nil
}

func startAttackPageServer(port int) (*http.Server, error) {
	// Get the path to the malicious page
	pageDir := filepath.Join(os.Getenv("HOME"), "go/src/github.com/grokify/threat-model-spec/demo/malicious-page")

	// Verify index.html exists
	indexPath := filepath.Join(pageDir, "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		return nil, fmt.Errorf("attack page not found at %s", indexPath)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: http.FileServer(http.Dir(pageDir)),
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("Page server error: %v", err)
		}
	}()

	return server, nil
}

func takeScreenshot(ctx context.Context, vibe *vibium.Vibe, outputDir, filename string) error {
	data, err := vibe.Screenshot(ctx)
	if err != nil {
		return err
	}

	outputPath := filepath.Join(outputDir, filename)
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	return nil
}
