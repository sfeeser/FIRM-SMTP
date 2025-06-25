package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
)

// --- Configuration Structs (for loading settings) ---

// Config holds all server and FIRM API related configurations.
type Config struct {
	ListenAddress     string `json:"listen_address"`
	ServerDomain      string `json:"server_domain"`
	MaxMessageBytes   int64  `json:"max_message_bytes"`
	MaxRecipients     int    `json:"max_recipients"`
	ReadTimeout       string `json:"read_timeout"`
	WriteTimeout      string `json:"write_timeout"`
	SessionIdleTimeout string `json:"session_idle_timeout"` // FIRM-SMTP spec: 60 seconds

	FirmAPIURL        string `json:"firm_api_url"`
	BanlistPollInterval string `json:"banlist_poll_interval"`

	TLSConfig TLSConfig `json:"tls"`
}

// TLSConfig holds TLS related configurations.
type TLSConfig struct {
	Enabled       bool   `json:"enabled"`
	UseACME       bool   `json:"use_acme"`
	ACMECertCacheDir string `json:"cert_cache_dir"`
	ACMEEmail     string `json:"acme_email"`
	ACMEDomain    string `json:"acme_domain"`
	ACMEAgreeTOS  bool   `json:"acme_agree_tos"`
	UsePEM        bool   `json:"use_pem"`
	PEMCertFile   string `json:"pem_cert_file"`
	PEMKeyFile    string `json:"pem_key_file"`
}

// --- Global State (for banlists and concurrency) ---

var (
	// BannedIPs stores currently banned IP addresses, updated by a background goroutine.
	bannedIPs = sync.Map{} // map[string]struct{} (IP string to empty struct)
	// BlockedEmails stores currently blocked email addresses, updated by a background goroutine.
	blockedEmails = sync.Map{} // map[string]struct{} (email string to empty struct)

	// MaxConcurrentSessions and MaxPerIPSessions from FIRM-SMTP spec.
	maxConcurrentSessions = 100
	maxPerIPSessions      = 5

	// Current session counters
	currentConcurrentSessions int32
	perIPSessionCounts        sync.Map // map[string]int32 (IP string to count)

	firmTokenRegex = regexp.MustCompile(`FIRM-TOKEN:[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}`)
)

// --- FIRMBackend: Implements smtp.Backend ---

// FIRMBackend is our custom SMTP backend implementation for FIRM-SMTP.
type FIRMBackend struct {
	firmAPIClient *FirmAPIClient
	serverConfig  *Config
}

// NewSession is called by the go-smtp server for every new client connection.
// It initializes a new FIRMSession.
func (be *FIRMBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	// Enforce max per-IP sessions
	remoteIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	count, _ := perIPSessionCounts.LoadOrStore(remoteIP, int32(0))
	if count.(int32) >= int32(maxPerIPSessions) {
		log.Printf("INFO: Rejecting new session from %s: max per-IP sessions (%d) exceeded", remoteIP, maxPerIPSessions)
		return nil, &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 3, 2},
			Message:      fmt.Sprintf("Too many sessions from your IP (%s). Try again later.", remoteIP),
		}
	}
	perIPSessionCounts.Store(remoteIP, count.(int32)+1)

	// Enforce max concurrent sessions
	if currentConcurrentSessions >= int32(maxConcurrentSessions) {
		log.Printf("INFO: Rejecting new session from %s: max concurrent sessions (%d) exceeded", remoteIP, maxConcurrentSessions)
		perIPSessionCounts.Store(remoteIP, count.(int32)) // Decrement counter if we reject
		return nil, &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 3, 2},
			Message:      "Server too busy. Please try again later.",
		}
	}
	currentConcurrentSessions++

	log.Printf("INFO: New session from %s (current: %d, IP sessions: %d)", remoteIP, currentConcurrentSessions, count.(int32)+1)

	// Check banlist (banned IPs) at connection time
	if _, isBanned := bannedIPs.Load(remoteIP); isBanned {
		log.Printf("WARN: Rejecting banned IP %s at connection", remoteIP)
		perIPSessionCounts.Store(remoteIP, count.(int32)) // Decrement counter if we reject
		currentConcurrentSessions--
		return nil, &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Your IP address is banned. Connection rejected.",
		}
	}

	return &FIRMSession{
		conn:          conn,
		firmAPIClient: be.firmAPIClient,
		serverConfig:  be.serverConfig,
		from:          "",
		rcpts:         []string{},
		remoteIP:      remoteIP,
		heloHostname:  conn.Hostname(), // The EHLO/HELO hostname is available here
	}, nil
}

// --- FIRMSession: Implements smtp.Session ---

// FIRMSession holds state for an individual SMTP session.
type FIRMSession struct {
	conn          *smtp.Conn // Reference to the underlying smtp.Conn to get remote IP, etc.
	firmAPIClient *FirmAPIClient
	serverConfig  *Config

	from         string
	rcpts        []string
	mailBody     bytes.Buffer // Buffer to store the email body including headers
	remoteIP     string       // Stored from Conn.RemoteAddr() for convenience
	heloHostname string       // Stored from Conn.Hostname()
}

// AuthMechanisms returns a slice of available authentication mechanisms.
// FIRM-SMTP does not require authentication, so it returns an empty slice.
func (s *FIRMSession) AuthMechanisms() []string {
	// FIRM-SMTP is receive-only and explicitly states "No authentication required"
	return []string{}
}

// Auth is called when a client attempts to authenticate.
func (s *FIRMSession) Auth(mech string) (sasl.Server, error) {
	// FIRM-SMTP does not support authentication.
	return nil, smtp.ErrAuthUnsupported
}

// Mail is called when a client sends the MAIL FROM command.
func (s *FIRMSession) Mail(from string, opts *smtp.MailOptions) error {
	log.Printf("DEBUG: Mail from: %s (IP: %s)", from, s.remoteIP)

	// Check banlist (blocked emails) at MAIL FROM
	if _, isBlocked := blockedEmails.Load(strings.ToLower(from)); isBlocked {
		log.Printf("WARN: Blocking email %s at MAIL FROM: email banned", from)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Sender address is blocked.",
		}
	}

	s.from = from
	s.mailBody.Reset() // Reset buffer for new message
	return nil
}

// Rcpt is called when a client sends the RCPT TO command.
// FIRM-SMTP only cares about the verification address.
func (s *FIRMSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	log.Printf("DEBUG: Rcpt to: %s (IP: %s)", to, s.remoteIP)

	// FIRM-SMTP is a receive-only gateway for 'firmserver@gmail.com'
	// It should only accept recipients that match its configured domain or specific verification address.
	// For simplicity, let's assume 'firmserver@gmail.com' is the target for now.
	// In a real implementation, this would be configurable and potentially involve checks against s.serverConfig.ServerDomain
	expectedRecipient := "firmserver@gmail.com" // As per FIRM spec example

	if strings.ToLower(to) != expectedRecipient {
		log.Printf("WARN: Rejecting recipient %s: not the expected FIRM verification address", to)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "Recipient not found or not supported by this server.",
		}
	}

	if len(s.rcpts) >= int(s.serverConfig.MaxRecipients) {
		log.Printf("WARN: Rejecting recipient %s: max recipients (%d) reached", to, s.serverConfig.MaxRecipients)
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      fmt.Sprintf("Maximum limit of %v recipients reached", s.serverConfig.MaxRecipients),
		}
	}

	s.rcpts = append(s.rcpts, to)
	return nil
}

// Data is called when a client sends the DATA command, providing the email content.
func (s *FIRMSession) Data(r io.Reader) error {
	if s.from == "" || len(s.rcpts) == 0 {
		log.Printf("ERROR: DATA command issued without MAIL FROM or RCPT TO. Session from: %s, rcpts: %v", s.from, s.rcpts)
		return &smtp.SMTPError{
			Code:         502,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Missing MAIL FROM or RCPT TO command.",
		}
	}

	log.Printf("INFO: Receiving DATA for from: %s, to: %v", s.from, s.rcpts)

	// Read the entire email message (headers + body) into the buffer
	n, err := io.Copy(&s.mailBody, io.LimitReader(r, s.serverConfig.MaxMessageBytes+1)) // +1 to detect overflow
	if err != nil {
		log.Printf("ERROR: Error reading DATA: %v", err)
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 4, 0},
			Message:      "Error reading message data.",
		}
	}

	if n > s.serverConfig.MaxMessageBytes {
		log.Printf("WARN: Message size exceeded limit of %d bytes for from: %s", s.serverConfig.MaxMessageBytes, s.from)
		return smtp.ErrDataTooLarge
	}

	fullMessage := s.mailBody.String()
	log.Printf("DEBUG: Full received message:\n%s", fullMessage)

	// Extract headers, subject, and plain text body
	headers, subject, body := parseEmailContent(fullMessage)

	// Extract FIRM-TOKEN using regex
	firmTokenMatch := firmTokenRegex.FindString(subject + " " + body) // Search in subject and body
	if firmTokenMatch == "" {
		log.Printf("WARN: No FIRM-TOKEN found in message from %s", s.from)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.5, 7, 0}, // Generic security/policy failure
			Message:      "Verification token not found or malformed.",
		}
	}
	firmToken := firmTokenMatch

	log.Printf("INFO: FIRM-TOKEN extracted: %s from email from %s", firmToken, s.from)

	// Prepare payload for FIRM /inbound API
	payload := FirmInboundPayload{
		Email:      s.from,
		Subject:    subject,
		Body:       body,
		Headers:    headers, // Pass all parsed headers
		SPFResult:  "none",  // Placeholder: SPF/DKIM checks would be done by the FIRM backend (or a dedicated mail-scanner service).
		DKIMResult: "none",  // The SMTP-FIRM spec says "SPF, DKIM, and domain mismatch do not block forwarding"
		ClientIP:   s.remoteIP,
		Helo:       s.heloHostname,
	}

	// Forward to FIRM API
	if err := s.firmAPIClient.PostInbound(payload); err != nil {
		log.Printf("ERROR: Failed to forward message to FIRM API for %s: %v", s.from, err)
		// Check for specific FIRM API errors that might map to SMTP responses
		if httpErr, ok := err.(*HTTPError); ok {
			if httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
				return &smtp.SMTPError{
					Code:         554, // Permanent failure
					EnhancedCode: smtp.EnhancedCode{5, 7, 0},
					Message:      fmt.Sprintf("FIRM API rejection: %s", httpErr.Message),
				}
			}
		}
		return &smtp.SMTPError{
			Code:         451, // Temporary failure
			EnhancedCode: smtp.EnhancedCode{4, 4, 0},
			Message:      "Internal server error when processing message.",
		}
	}

	log.Printf("INFO: Message from %s successfully forwarded to FIRM API. Token: %s", s.from, firmToken)
	return nil
}

// Reset resets the session state as per RFC 5321.
func (s *FIRMSession) Reset() {
	s.from = ""
	s.rcpts = []string{}
	s.mailBody.Reset()
	log.Printf("DEBUG: Session reset for %s", s.remoteIP)
}

// Logout is called when a client sends the QUIT command or the connection is closed.
func (s *FIRMSession) Logout() error {
	remoteIP := s.remoteIP
	if count, ok := perIPSessionCounts.Load(remoteIP); ok {
		newCount := count.(int32) - 1
		if newCount <= 0 {
			perIPSessionCounts.Delete(remoteIP)
		} else {
			perIPSessionCounts.Store(remoteIP, newCount)
		}
	}
	currentConcurrentSessions--
	log.Printf("INFO: Session logged out for %s (current: %d, IP sessions: %d)", remoteIP, currentConcurrentSessions, func() int32 { c, _ := perIPSessionCounts.Load(remoteIP); return c.(int32) }())
	return nil
}

// --- FIRM API Client (for POST /inbound and banlist polling) ---

// FirmInboundPayload represents the JSON structure sent to FIRM's /inbound endpoint.
type FirmInboundPayload struct {
	Email      string            `json:"email"`
	Subject    string            `json:"subject"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers"`
	SPFResult  string            `json:"spf_result"`  // "pass", "fail", "none", etc.
	DKIMResult string            `json:"dkim_result"` // "pass", "fail", "none", etc.
	ClientIP   string            `json:"client_ip"`
	Helo       string            `json:"helo"`
}

// FirmBanlistPayload represents a simplified structure for banlist data.
// This would need to match the actual API response from FIRM.
type FirmBanlistPayload struct {
	Subnets []string `json:"banned_subnets"` // e.g., ["192.168.1.0/24"]
	Emails  []string `json:"blocked_emails"` // e.g., ["spam@example.com"]
}

// HTTPError custom error for API calls
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP error %d: %s", e.StatusCode, e.Message)
}


// FirmAPIClient handles communication with the FIRM API server.
type FirmAPIClient struct {
	baseURL string
	client  *http.Client
}

// NewFirmAPIClient creates a new client for the FIRM API.
func NewFirmAPIClient(baseURL string) *FirmAPIClient {
	return &FirmAPIClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second}, // Basic timeout
	}
}

// PostInbound sends the email data to the FIRM /inbound endpoint.
func (c *FirmAPIClient) PostInbound(payload FirmInboundPayload) error {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal inbound payload: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/inbound", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create /inbound request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send /inbound request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Message:    string(respBody),
		}
	}

	log.Printf("DEBUG: /inbound POST successful for %s", payload.Email)
	return nil
}

// GetBanlists fetches banned subnets and blocked emails from the FIRM API.
func (c *FirmAPIClient) GetBanlists() (FirmBanlistPayload, error) {
	var banlist FirmBanlistPayload

	// Fetch banned subnets
	req, err := http.NewRequest("GET", c.baseURL+"/admin/banned_subnets", nil)
	if err != nil {
		return banlist, fmt.Errorf("failed to create /banned_subnets request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return banlist, fmt.Errorf("failed to fetch /banned_subnets: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return banlist, &HTTPError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("Failed to fetch banned subnets: %s", string(respBody)),
		}
	}
	// Assuming the response is a JSON array of strings or a struct with a "subnets" field
	var subnets []string
	if err := json.NewDecoder(resp.Body).Decode(&subnets); err != nil {
		return banlist, fmt.Errorf("failed to decode banned subnets: %w", err)
	}
	banlist.Subnets = subnets

	// Fetch blocked emails
	req, err = http.NewRequest("GET", c.baseURL+"/admin/blocked_emails", nil)
	if err != nil {
		return banlist, fmt.Errorf("failed to create /blocked_emails request: %w", err)
	}
	resp, err = c.client.Do(req)
	if err != nil {
		return banlist, fmt.Errorf("failed to fetch /blocked_emails: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return banlist, &HTTPError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("Failed to fetch blocked emails: %s", string(respBody)),
		}
	}
	// Assuming the response is a JSON array of strings or a struct with an "emails" field
	var emails []string
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return banlist, fmt.Errorf("failed to decode blocked emails: %w", err)
	}
	banlist.Emails = emails

	return banlist, nil
}


// --- Helper Functions ---

// parseEmailContent extracts headers, subject, and body from a raw email message.
// This is a simplified parser. A full RFC-compliant parser would be more complex.
func parseEmailContent(rawEmail string) (headers map[string]string, subject, body string) {
	headers = make(map[string]string)
	lines := strings.Split(rawEmail, "\n")
	headerBoundary := -1

	// Parse headers
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			headerBoundary = i
			break
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// Continuation of previous header
			if len(headers) > 0 {
				var lastHeaderKey string
				for k := range headers { // Get the last key
					lastHeaderKey = k
				}
				headers[lastHeaderKey] += strings.TrimSpace(line)
			}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers[strings.ToLower(key)] = value // Store keys in lowercase for easy lookup
		}
	}

	subject = headers["subject"] // Subject is typically in headers

	// Extract body
	if headerBoundary != -1 {
		body = strings.Join(lines[headerBoundary+1:], "\n")
	} else {
		// No header boundary found, assume whole message is body (less common for emails)
		body = rawEmail
	}

	return headers, subject, body
}

// setupTLSConfig loads PEM files or configures ACME.
// Placeholder for real ACME implementation using certmagic/autocert.
func setupTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil // TLS disabled
	}

	if cfg.UseACME {
		// TODO: Implement ACME DNS-01 automation using a library like CertMagic
		// or autocert. This would typically involve:
		// 1. Initializing a certificate manager.
		// 2. Configuring a storage backend (cfg.ACMECertCacheDir).
		// 3. Setting up DNS-01 challenge provider (e.g., for Route 53).
		// 4. Returning a *tls.Config from the certificate manager.
		log.Printf("INFO: ACME enabled for domain %s. Real ACME setup required.", cfg.ACMEDomain)
		// For now, return a dummy config or error if no PEM fallback.
		if cfg.UsePEM {
			log.Println("WARN: ACME is enabled but using static PEM files as fallback for demonstration.")
			return loadPEMFiles(cfg)
		}
		return nil, fmt.Errorf("ACME implementation is a placeholder; requires a real library setup")
	} else if cfg.UsePEM {
		return loadPEMFiles(cfg)
	}

	return nil, fmt.Errorf("TLS is enabled but neither ACME nor PEM files are configured correctly")
}

// loadPEMFiles loads TLS certificates from PEM files.
func loadPEMFiles(cfg *TLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.PEMCertFile, cfg.PEMKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS PEM files: %w", err)
	}
	log.Printf("INFO: Loaded TLS certificate from %s and %s", cfg.PEMCertFile, cfg.PEMKeyFile)
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// startBanlistPolling starts a goroutine to periodically fetch banlists.
func startBanlistPolling(client *FirmAPIClient, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial fetch
	fetchAndSetBanlists(client)

	for range ticker.C {
		fetchAndSetBanlists(client)
	}
}

// fetchAndSetBanlists fetches banlists and updates the global sync.Maps.
func fetchAndSetBanlists(client *FirmAPIClient) {
	log.Println("INFO: Fetching banlists from FIRM API...")
	payload, err := client.GetBanlists()
	if err != nil {
		log.Printf("ERROR: Failed to fetch banlists: %v", err)
		// TODO: POST to FIRM /admin/alarm with failure details if this is a persistent issue
		return
	}

	// Update bannedIPs
	newBannedIPs := sync.Map{}
	for _, ip := range payload.Subnets { // Assuming "subnets" contains individual IPs or CIDRs to ban
		// For simplicity, treating CIDRs as individual IPs for now.
		// A full implementation would parse CIDRs and check if remoteIP falls within the range.
		newBannedIPs.Store(ip, struct{}{})
		log.Printf("DEBUG: Banned IP/Subnet loaded: %s", ip)
	}
	bannedIPs = newBannedIPs // Replace old map atomically

	// Update blockedEmails
	newBlockedEmails := sync.Map{}
	for _, email := range payload.Emails {
		newBlockedEmails.Store(strings.ToLower(email), struct{}{})
		log.Printf("DEBUG: Blocked email loaded: %s", email)
	}
	blockedEmails = newBlockedEmails // Replace old map atomically

	log.Println("INFO: Banlists updated successfully.")
}

// --- Main Function ---

func main() {
	log.SetOutput(os.Stdout) // FIRM-SMTP spec: "Log to stdout only"
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile) // Add file/line for DEBUG

	// Load configuration
	configPath := os.Getenv("FIRM_SMTP_CONFIG")
	if configPath == "" {
		configPath = "config.json" // Default config file name
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Parse durations from config strings
	readTimeout, err := time.ParseDuration(cfg.ReadTimeout)
	if err != nil {
		log.Fatalf("Invalid read_timeout duration: %v", err)
	}
	writeTimeout, err := time.ParseDuration(cfg.WriteTimeout)
	if err != nil {
		log.Fatalf("Invalid write_timeout duration: %v", err)
	}
	banlistPollInterval, err := time.ParseDuration(cfg.BanlistPollInterval)
	if err != nil {
		log.Fatalf("Invalid banlist_poll_interval duration: %v", err)
	}

	// Initialize FIRM API client
	firmAPIClient := NewFirmAPIClient(cfg.FirmAPIURL)

	// Start banlist polling in a goroutine
	go startBanlistPolling(firmAPIClient, banlistPollInterval)

	// Setup TLS config
	tlsConfig, err := setupTLSConfig(&cfg.TLSConfig)
	if err != nil {
		log.Fatalf("Failed to setup TLS configuration: %v", err)
	}

	// Create and configure the go-smtp server
	be := &FIRMBackend{
		firmAPIClient: firmAPIClient,
		serverConfig:  cfg,
	}

	s := smtp.NewServer(be)
	s.Addr = cfg.ListenAddress
	s.Domain = cfg.ServerDomain
	s.ReadTimeout = readTimeout
	s.WriteTimeout = writeTimeout
	s.MaxMessageBytes = cfg.MaxMessageBytes
	s.MaxRecipients = cfg.MaxRecipients
	s.AllowInsecureAuth = false // FIRM-SMTP is receive-only, no auth needed
	s.TLSConfig = tlsConfig
	s.ErrorLog = log.New(os.Stderr, "smtp/server ERROR: ", log.LstdFlags) // Separate logger for smtp errors

	log.Printf("INFO: Starting FIRM-SMTP server at %s for domain %s", s.Addr, s.Domain)
	if tlsConfig != nil {
		log.Println("INFO: TLS (STARTTLS) enabled.")
	}

	// Start the SMTP server
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("FIRM-SMTP server failed: %v", err)
	}
}

// loadConfig reads the configuration from a JSON file.
func loadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config JSON from %s: %w", path, err)
	}

	// Apply FIRM-SMTP hard-coded defaults if not overridden by config (e.g. for concurrency limits)
	// These values are hard-coded in the spec "cannot be changed at runtime."
	// Max concurrent sessions and max per-IP sessions are handled directly in NewSession.

	log.Printf("INFO: Configuration loaded from %s", path)
	return &cfg, nil
}
