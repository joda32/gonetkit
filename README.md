# gonetkit

Standalone network security tools written in Go. No Python, no dependencies, no installers — just static binaries you can drop on a box and run.

Built for pentesters and red teamers who are tired of fighting Python environments on engagement machines. Each tool ships as a single binary for Linux and Windows, with NTLM hash authentication and SOCKS proxy support baked in.

## Tools

| Tool | Description |
|------|-------------|
| **smbexec** | Semi-interactive shell via SCM service creation over SMB |
| **secretsdump** | Dump SAM hashes, cached credentials, and LSA secrets from remote hosts |

## Quick Start

```bash
make            # build all tools to build/
make release    # build release archives for Linux + Windows
```

See the [wiki](https://github.com/joda32/gonetkit/wiki) for build instructions, usage examples, and detection guidance.

## Legal

For authorized security testing and educational use only. Get written permission before you point these at anything.

## License

MIT
