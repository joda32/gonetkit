package credentials

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"golang.org/x/net/proxy"
)

type Credentials struct {
	Target   string
	TargetIP string
	Port     int
	Domain   string
	Username string
	Password string
	Hash     string
	Proxy    string
	NoPass   bool
	Debug    bool
}

func (c *Credentials) RegisterFlags(f *flag.FlagSet) {
	f.IntVar(&c.Port, "port", 445, "Destination port (139 or 445)")
	f.StringVar(&c.TargetIP, "target-ip", "", "IP address of the target (if different from hostname)")
	f.StringVar(&c.Hash, "hashes", "", "NTLM hash in LMHASH:NTHASH format")
	f.StringVar(&c.Proxy, "proxy", "", "SOCKS proxy URL (socks4://host:port or socks5://user:pass@host:port)")
	f.BoolVar(&c.NoPass, "no-pass", false, "Don't ask for password")
	f.BoolVar(&c.Debug, "debug", false, "Enable debug output")
}

func (c *Credentials) ParseTarget(target string) {
	host := target
	if idx := strings.LastIndex(host, "@"); idx >= 0 {
		userPart := host[:idx]
		host = host[idx+1:]
		if idx := strings.Index(userPart, "/"); idx >= 0 {
			c.Domain = userPart[:idx]
			userPart = userPart[idx+1:]
		}
		if idx := strings.Index(userPart, ":"); idx >= 0 {
			c.Username = userPart[:idx]
			c.Password = userPart[idx+1:]
		} else {
			c.Username = userPart
		}
	}
	c.Target = host
	if c.TargetIP == "" {
		c.TargetIP = host
	}
}

func (c *Credentials) PromptPassword() {
	if c.Password == "" && c.Username != "" && c.Hash == "" && !c.NoPass {
		fmt.Fprint(os.Stderr, "Password: ")
		reader := bufio.NewReader(os.Stdin)
		pw, _ := reader.ReadString('\n')
		c.Password = strings.TrimRight(pw, "\r\n")
	}
}

func (c *Credentials) SMBOptions() (smb.Options, error) {
	initiator := &spnego.NTLMInitiator{
		User:     c.Username,
		Password: c.Password,
		Domain:   c.Domain,
	}

	if c.Hash != "" {
		parts := strings.Split(c.Hash, ":")
		var nthash string
		if len(parts) == 2 {
			nthash = parts[1]
		} else {
			nthash = parts[0]
		}
		hashBytes, err := hex.DecodeString(nthash)
		if err != nil {
			return smb.Options{}, fmt.Errorf("invalid NT hash: %w", err)
		}
		initiator.Hash = hashBytes
		initiator.Password = ""
	}

	opts := smb.Options{
		Host:      c.TargetIP,
		Port:      c.Port,
		Initiator: initiator,
	}

	if c.Proxy != "" {
		dialer, err := proxyDialerFromURL(c.Proxy)
		if err != nil {
			return smb.Options{}, fmt.Errorf("proxy: %w", err)
		}
		opts.ProxyDialer = dialer
	}

	return opts, nil
}

func proxyDialerFromURL(rawURL string) (proxy.Dialer, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	switch u.Scheme {
	case "socks4", "socks4a", "socks5", "socks5h", "socks":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use socks4, socks5, or socks5h)", u.Scheme)
	}

	var auth *proxy.Auth
	if u.User != nil {
		auth = &proxy.Auth{User: u.User.Username()}
		if p, ok := u.User.Password(); ok {
			auth.Password = p
		}
	}

	return proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
}
