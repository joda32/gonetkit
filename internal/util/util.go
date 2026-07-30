package util

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

var serviceWords = []string{
	"agent", "backup", "bridge", "broker", "buffer", "cache",
	"census", "cipher", "client", "clouda", "config", "consul",
	"daemon", "deploy", "digest", "docker", "driver", "engine",
	"envoy", "events", "fabric", "falcon", "fluentd", "forwardr",
	"gateway", "grafana", "grpcsvr", "guard", "handler", "health",
	"helper", "hybrid", "index", "ingest", "intake", "kernel",
	"kubelet", "launch", "leader", "linker", "loader", "logger",
	"manage", "mapper", "master", "metric", "mirror", "module",
	"monitor", "netmon", "notify", "oracle", "parser", "patrol",
	"pilotr", "policy", "portal", "primer", "probes", "procmgr",
	"provdr", "pusher", "queued", "ranger", "reader", "redist",
	"registr", "relays", "render", "report", "router", "runner",
	"sample", "schema", "scoutr", "search", "sensor", "server",
	"signal", "socket", "source", "splunk", "sqlite", "stackr",
	"stream", "subnet", "svcmgr", "switch", "syslog", "tacker",
	"telnet", "tenant", "thread", "ticker", "tracer", "tunnel",
	"update", "uplink", "vector", "vertex", "vmotion", "warden",
	"watchr", "webapi", "worker", "writer",
}

func RandomServiceName() string {
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(serviceWords))))
	return "svc-" + serviceWords[idx.Int64()]
}

func RandomName(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[idx.Int64()]
	}
	return string(b)
}

func EncodePowerShell(cmd string) string {
	runes := []rune(cmd)
	utf16 := make([]byte, len(runes)*2)
	for i, r := range runes {
		utf16[i*2] = byte(r)
		utf16[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(utf16)
}
