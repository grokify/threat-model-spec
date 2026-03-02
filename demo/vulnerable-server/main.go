// Vulnerable WebSocket Server - Educational Demo
//
// ⚠️  WARNING: This server is INTENTIONALLY VULNERABLE ⚠️
//
// This code demonstrates the OpenClaw WebSocket localhost takeover vulnerability.
// It is designed for EDUCATIONAL PURPOSES ONLY to help security professionals
// understand the attack vector.
//
// DO NOT:
// - Run this in production
// - Expose this to untrusted networks
// - Use this code as a template for real applications
//
// The vulnerabilities demonstrated:
// 1. No rate limiting on password attempts from localhost
// 2. Auto-approve device pairing from localhost connections
// 3. WebSocket accepts connections without origin validation
//
// Run: go run main.go
// The server will listen on localhost:9999
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Config holds server configuration
type Config struct {
	Port     int
	Password string
}

// Session represents an authenticated session
type Session struct {
	ID            string    `json:"id"`
	DeviceName    string    `json:"deviceName"`
	Authenticated bool      `json:"authenticated"`
	RegisteredAt  time.Time `json:"registeredAt"`
}

// MockData represents sensitive data that would be exfiltrated
type MockData struct {
	APIKeys     map[string]string `json:"apiKeys"`
	Logs        []string          `json:"logs"`
	ConfigFiles map[string]string `json:"configFiles"`
	Devices     []string          `json:"devices"`
}

// Server is the vulnerable WebSocket server
type Server struct {
	config       Config
	sessions     map[string]*Session
	sessionsLock sync.RWMutex
	mockData     MockData
	upgrader     websocket.Upgrader
	authAttempts int // Track auth attempts (but don't limit them!)
}

// Message represents a WebSocket message
type Message struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// AuthPayload for authentication requests
type AuthPayload struct {
	Password string `json:"password"`
}

// RegisterPayload for device registration
type RegisterPayload struct {
	DeviceName string `json:"deviceName"`
}

// CommandPayload for agent commands
type CommandPayload struct {
	Command string `json:"command"`
	Args    string `json:"args,omitempty"`
}

// Response represents a server response
type Response struct {
	Type    string      `json:"type"`
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func NewServer(config Config) *Server {
	return &Server{
		config:   config,
		sessions: make(map[string]*Session),
		mockData: MockData{
			APIKeys: map[string]string{
				"OPENAI_API_KEY":  "sk-fake-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"AWS_ACCESS_KEY":  "AKIAFAKEXXXXXXXXXX",
				"AWS_SECRET_KEY":  "fake+secret+key+xxxxxxxxxxxxxxxxxxxxxxxx",
				"GITHUB_TOKEN":    "ghp_fakeTOKENxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"SLACK_BOT_TOKEN": "xoxb-fake-token-xxxxxxxxxxxxxxxxxxxxxxxx",
			},
			Logs: []string{
				"[2026-02-26 10:00:01] Agent started successfully",
				"[2026-02-26 10:00:02] Connected to AI provider: OpenAI",
				"[2026-02-26 10:00:03] Loaded 5 plugins from ClawHub",
				"[2026-02-26 10:15:22] User query: 'Search my Slack for API keys'",
				"[2026-02-26 10:15:25] Agent response: Found 3 messages containing credentials",
				"[2026-02-26 11:30:00] User query: 'Read my ~/.ssh/config'",
				"[2026-02-26 11:30:01] Agent response: SSH config loaded successfully",
			},
			ConfigFiles: map[string]string{
				"gateway.yaml":    "port: 9999\nauth: password\npassword_hash: abc123...",
				"plugins.yaml":    "enabled:\n  - slack\n  - github\n  - calendar",
				"credentials.enc": "[ENCRYPTED] But we have the key in memory...",
			},
			Devices: []string{
				"MacBook Pro (John's Laptop)",
				"iPhone 15 Pro",
				"iPad Air",
			},
		},
		upgrader: websocket.Upgrader{
			// VULNERABILITY: Accept connections from any origin
			// A secure implementation would validate the Origin header
			CheckOrigin: func(r *http.Request) bool {
				log.Printf("⚠️  Connection from origin: %s (accepting without validation)", r.Header.Get("Origin"))
				return true
			},
		},
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()

	log.Printf("📡 New WebSocket connection from %s", r.RemoteAddr)

	// Session state for this connection
	var session *Session

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		response := s.handleMessage(msg, &session, r.RemoteAddr)
		if err := conn.WriteJSON(response); err != nil {
			log.Printf("Write error: %v", err)
			break
		}
	}

	log.Printf("📴 Connection closed from %s", r.RemoteAddr)
}

func (s *Server) handleMessage(msg Message, session **Session, remoteAddr string) Response {
	switch msg.Type {
	case "auth":
		return s.handleAuth(msg.Payload, session, remoteAddr)
	case "register":
		return s.handleRegister(msg.Payload, session, remoteAddr)
	case "command":
		return s.handleCommand(msg.Payload, *session)
	case "getConfig":
		return s.handleGetConfig(*session)
	case "getLogs":
		return s.handleGetLogs(*session)
	case "getDevices":
		return s.handleGetDevices(*session)
	default:
		return Response{Type: "error", Success: false, Error: "unknown message type"}
	}
}

func (s *Server) handleAuth(payload json.RawMessage, session **Session, remoteAddr string) Response {
	var auth AuthPayload
	if err := json.Unmarshal(payload, &auth); err != nil {
		return Response{Type: "auth", Success: false, Error: "invalid payload"}
	}

	s.authAttempts++

	// VULNERABILITY: No rate limiting!
	// A secure implementation would:
	// - Track failed attempts per IP
	// - Implement exponential backoff
	// - Lock accounts after N failures
	// - Use constant-time comparison
	log.Printf("🔑 Auth attempt #%d from %s (password: %s)", s.authAttempts, remoteAddr, maskPassword(auth.Password))

	if auth.Password == s.config.Password {
		*session = &Session{
			ID:            fmt.Sprintf("session-%d", time.Now().UnixNano()),
			Authenticated: true,
		}
		log.Printf("✅ Authentication successful! Session: %s", (*session).ID)
		return Response{
			Type:    "auth",
			Success: true,
			Data:    map[string]string{"sessionId": (*session).ID},
		}
	}

	// VULNERABILITY: Doesn't slow down after failures
	log.Printf("❌ Authentication failed (attempt #%d)", s.authAttempts)
	return Response{Type: "auth", Success: false, Error: "invalid password"}
}

func (s *Server) handleRegister(payload json.RawMessage, session **Session, remoteAddr string) Response {
	if *session == nil || !(*session).Authenticated {
		return Response{Type: "register", Success: false, Error: "not authenticated"}
	}

	var reg RegisterPayload
	if err := json.Unmarshal(payload, &reg); err != nil {
		return Response{Type: "register", Success: false, Error: "invalid payload"}
	}

	// VULNERABILITY: Auto-approve device registration from localhost
	// A secure implementation would:
	// - Require user confirmation via UI
	// - Send notification to user
	// - Require additional authentication
	isLocalhost := isLocalhostConnection(remoteAddr)
	if isLocalhost {
		log.Printf("⚠️  AUTO-APPROVING device registration from localhost (no user confirmation!)")
	}

	(*session).DeviceName = reg.DeviceName
	(*session).RegisteredAt = time.Now()

	s.sessionsLock.Lock()
	s.sessions[(*session).ID] = *session
	s.sessionsLock.Unlock()

	log.Printf("📱 Device registered: %s (auto-approved: %v)", reg.DeviceName, isLocalhost)

	return Response{
		Type:    "register",
		Success: true,
		Data: map[string]interface{}{
			"deviceName":   reg.DeviceName,
			"registeredAt": (*session).RegisteredAt,
			"autoApproved": isLocalhost,
		},
	}
}

func (s *Server) handleCommand(payload json.RawMessage, session *Session) Response {
	if session == nil || !session.Authenticated {
		return Response{Type: "command", Success: false, Error: "not authenticated"}
	}

	var cmd CommandPayload
	if err := json.Unmarshal(payload, &cmd); err != nil {
		return Response{Type: "command", Success: false, Error: "invalid payload"}
	}

	log.Printf("🤖 Executing command: %s %s", cmd.Command, cmd.Args)

	// Simulate agent command execution
	switch cmd.Command {
	case "search":
		return Response{
			Type:    "command",
			Success: true,
			Data: map[string]interface{}{
				"command": cmd.Command,
				"results": []string{
					"Found: API key in ~/.env",
					"Found: Database credentials in config.yaml",
					"Found: SSH key passphrase in notes.txt",
				},
			},
		}
	case "read":
		return Response{
			Type:    "command",
			Success: true,
			Data: map[string]interface{}{
				"command": cmd.Command,
				"content": "# Sensitive file contents would appear here\nSECRET_KEY=supersecret123",
			},
		}
	case "execute":
		return Response{
			Type:    "command",
			Success: true,
			Data: map[string]interface{}{
				"command": cmd.Command,
				"output":  "Command executed successfully on connected device",
			},
		}
	default:
		return Response{
			Type:    "command",
			Success: true,
			Data: map[string]interface{}{
				"command": cmd.Command,
				"output":  "Agent processed command",
			},
		}
	}
}

func (s *Server) handleGetConfig(session *Session) Response {
	if session == nil || !session.Authenticated {
		return Response{Type: "getConfig", Success: false, Error: "not authenticated"}
	}

	log.Printf("📄 Exfiltrating configuration data...")

	return Response{
		Type:    "getConfig",
		Success: true,
		Data: map[string]interface{}{
			"apiKeys":     s.mockData.APIKeys,
			"configFiles": s.mockData.ConfigFiles,
		},
	}
}

func (s *Server) handleGetLogs(session *Session) Response {
	if session == nil || !session.Authenticated {
		return Response{Type: "getLogs", Success: false, Error: "not authenticated"}
	}

	log.Printf("📜 Exfiltrating log data...")

	return Response{
		Type:    "getLogs",
		Success: true,
		Data:    s.mockData.Logs,
	}
}

func (s *Server) handleGetDevices(session *Session) Response {
	if session == nil || !session.Authenticated {
		return Response{Type: "getDevices", Success: false, Error: "not authenticated"}
	}

	log.Printf("📱 Enumerating connected devices...")

	return Response{
		Type:    "getDevices",
		Success: true,
		Data:    s.mockData.Devices,
	}
}

func isLocalhostConnection(remoteAddr string) bool {
	// In a real scenario, this would check if the connection originates from localhost
	// For demo purposes, we assume all connections are from localhost
	return true
}

func maskPassword(password string) string {
	if len(password) <= 2 {
		return "**"
	}
	return password[:1] + "***" + password[len(password)-1:]
}

func main() {
	port := flag.Int("port", 9999, "Port to listen on")
	password := flag.String("password", "demo123", "Authentication password")
	flag.Parse()

	fmt.Print(`
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ⚠️  VULNERABLE WEBSOCKET SERVER - EDUCATIONAL DEMO ⚠️              ║
║                                                                      ║
║   This server demonstrates the OpenClaw localhost takeover          ║
║   vulnerability. It is INTENTIONALLY INSECURE.                       ║
║                                                                      ║
║   Vulnerabilities:                                                   ║
║   • No rate limiting on authentication                               ║
║   • Auto-approve device registration from localhost                  ║
║   • No WebSocket origin validation                                   ║
║                                                                      ║
║   DO NOT use this code in production!                                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
`)

	config := Config{
		Port:     *port,
		Password: *password,
	}

	server := NewServer(config)

	http.HandleFunc("/ws", server.handleWebSocket)
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	addr := fmt.Sprintf("localhost:%d", config.Port)
	log.Printf("🚀 Starting vulnerable server on %s", addr)
	log.Printf("🔑 Password: %s", config.Password)
	log.Printf("📡 WebSocket endpoint: ws://%s/ws", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
