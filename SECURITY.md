# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Slipstream MCP server, please report it responsibly.

**Email:** security@keyq.cloud

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response time:** We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

**Please do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Exploit the vulnerability beyond what is necessary to demonstrate it
- Access or modify other users' data

## Supported Versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| < 0.2 | No |

## Security Measures

- Personal API tokens are SHA-256 hashed (never stored in plaintext)
- Timing-safe comparison for token verification
- Dangerous command detection and warnings
- Rate limiting (60 commands/minute per device)
- 30-second execution timeout
- 1MB output cap
- Agent strips credentials from command environment
- `exec:command` permission required (not granted by default)
- Full audit trail on every command execution

## Disclosure Policy

We follow responsible disclosure. Once a fix is available, we will:
1. Release a patched version
2. Publish a security advisory on GitHub
3. Notify affected users if applicable
