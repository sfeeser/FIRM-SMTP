# FIRM-SMTP
SMTP Server for FIRM

Current Implementation:

main.go: Sets up the smtp.Server with configuration loaded from a config.json file (or FIRM_SMTP_CONFIG env var). It initializes the FIRMBackend, FirmAPIClient, and starts the banlist polling.

FIRMBackend: Implements smtp.Backend. Its NewSession method handles initial connection-level checks:

Concurrency Limits: Enforces max concurrent sessions (100) and max per-IP sessions (5) as hard-coded values from the FIRM-SMTP spec. It uses sync.Map and int32 for atomic session counting.

Banned IPs: Checks bannedIPs sync.Map (populated by the poller) and rejects connections from banned IPs.

FIRMSession: Implements smtp.Session.

AuthMechanisms / Auth: Explicitly returns unsupported errors, as FIRM-SMTP is receive-only and requires no authentication.

Mail: Performs the MAIL FROM command. It checks blockedEmails sync.Map to reject messages from blocked senders.

Rcpt: Performs the RCPT TO command. It's currently hard-coded to accept only firmserver@gmail.com as the recipient, matching the FIRM spec's example. It also enforces MaxRecipients.

Data: Reads the entire email message, parses headers (simplistically for now), extracts the subject and body, and crucially, uses the firmTokenRegex to find the FIRM-TOKEN. It then constructs the FirmInboundPayload and calls firmAPIClient.PostInbound.

Reset / Logout: Cleans up session state and decrements session counters appropriately.

FirmAPIClient: A dedicated client for interacting with the FIRM backend API (/inbound, /admin/banned_subnets, /admin/blocked_emails). It includes basic HTTP error handling.

Helper Functions:

parseEmailContent: A simplified function to extract headers, subject, and body from the raw email stream. This will need significant enhancement for robust, RFC-compliant email parsing.

setupTLSConfig / loadPEMFiles: Placeholders for TLS configuration. The ACME part is currently a comment, emphasizing that a dedicated ACME library (like CertMagic) would integrate here.

startBanlistPolling / fetchAndSetBanlists: Implements the periodic polling of FIRM's /admin/banned_subnets and /admin/blocked_emails endpoints every 60 seconds (configurable).

To Run This Code:

You would need to create a config.json file in the same directory as your Go code (or specify its path via the FIRM_SMTP_CONFIG environment variable).

Example config.json:

```JSON

{
  "listen_address": "0.0.0.0:2525",
  "server_domain": "mail.firm.example.com",
  "max_message_bytes": 20000,
  "max_recipients": 1,
  "read_timeout": "60s",
  "write_timeout": "60s",
  "session_idle_timeout": "60s",
  "firm_api_url": "http://localhost:8080",
  "banlist_poll_interval": "60s",
  "tls": {
    "enabled": false,
    "use_acme": false,
    "cert_cache_dir": "",
    "acme_email": "",
    "acme_domain": "",
    "acme_agree_tos": false,
    "use_pem": false,
    "pem_cert_file": "",
    "pem_key_file": ""
  }
}
```

Next Steps / Areas for Improvement:

Robust Email Parsing: The parseEmailContent function is very basic. A production-ready server would need a more sophisticated email parsing library (e.g., net/mail or go-message/mail) to correctly handle multi-part MIME, various header encodings, and extract plain text bodies reliably.

SPF/DKIM/Domain Mismatch (at FIRM Backend): While the SMTP-FIRM spec says these don't block forwarding, the FIRM spec says the server (i.e., the backend) validates SPF/DKIM. The current PostInbound payload sends "none" for these. The FIRM-SMTP server could optionally perform these checks itself before forwarding, or rely entirely on the backend as currently implied. If the SMTP-FIRM server is to generate these, it would require additional libraries (e.g., miekg/dns for SPF, a DKIM library).

TLS Automation (setupTLSConfig): Integrate a real ACME client library (like github.com/caddyserver/certmagic or golang.org/x/crypto/acme/autocert) if tls.use_acme is true. This is a significant piece of functionality.

Error Handling and Logging: Enhance error logging to meet the "Structured JSON logs" requirement (e.g., using logrus or zap). Implement ErrorHandler for smtp.Server.

Subnet Banning: The current banlist polling simply stores IP strings. For subnets, it would need to parse CIDR notations (net.ParseCIDR) and implement a lookup logic to check if a client IP falls within a banned range.

Malformed SMTP Command Tracking: Implement the "After 3 violations, the connection is dropped with a 421 response" for malformed commands (protocolError in go-smtp already does this to some extent, but custom tracking might be needed if you want more granular control or logging specifically for this).

Runtime and CLI Behavior: Implement --version, --help, --check-cert, --config CLI flags using a library like spf13/cobra or urfave/cli. Implement the /healthz endpoint using a simple HTTP server alongside the SMTP server.

Graceful Shutdown: Ensure s.Shutdown() is called on SIGINT/SIGTERM signals.

This is a solid start for the FIRM-SMTP server based on your specifications and the go-smtp library.
