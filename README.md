# gonetkit

A collection of Go-based network security tools for penetration testing and red team engagements. Each tool is a standalone static binary — no runtime dependencies, no interpreters, just copy and run.

## Tools

| Tool | Description |
|------|-------------|
| **smbexec** | Remote command execution via the Windows Service Control Manager (SCM) over SMB |

## Building

Requires Go 1.21+.

```bash
# Build all tools
make

# Build a specific tool
make smbexec

# Build release archives (Linux tar.gz + Windows zip)
make release

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 make smbexec
```

Binaries are placed in `build/`.

## Usage

### smbexec

Execute commands on a remote Windows host via SCM service creation. Provides a semi-interactive shell.

```bash
# Password authentication
smbexec 'domain/user:password@target'

# Pass-the-hash
smbexec -hashes 'aad3b435b51404ee:e19ccf75ee54e06b' 'domain/user@target'

# PowerShell mode
smbexec -shell-type powershell 'user:password@target'

# Via SOCKS proxy
smbexec -proxy socks5://127.0.0.1:1080 'user:password@target'

# Custom share for output retrieval
smbexec -share ADMIN$ 'user:password@target'
```

**Options:**

```
  -share string        Share for output retrieval (default "C$")
  -shell-type string   cmd or powershell (default "cmd")
  -port int            Destination port (default 445)
  -target-ip string    IP of the target (if different from hostname)
  -service-name string Custom service name (default: random)
  -hashes string       NTLM hash, LMHASH:NTHASH format
  -no-pass             Don't prompt for password
  -proxy string        SOCKS proxy (socks5://host:port)
  -debug               Enable debug output
```

## Project Structure

```
gonetkit/
├── cmd/
│   └── smbexec/        # Remote execution via SCM
├── internal/
│   ├── credentials/    # Shared auth & target parsing
│   └── util/           # Shared helpers
├── Makefile
└── go.mod
```

## Adding New Tools

1. Create `cmd/<toolname>/main.go`
2. Use `internal/credentials` for auth flags and SMB connection setup
3. Use `internal/util` for shared helpers
4. Run `make` — the Makefile auto-discovers tools under `cmd/`

## Legal

This software is intended for authorized security testing, penetration testing engagements, and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper written authorization before testing.

## License

MIT
