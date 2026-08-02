package api

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)
	requestFallback  atomic.Uint64
)

func requestID(request *http.Request) string {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 1 && requestIDPattern.MatchString(values[0]) {
		return values[0]
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	counter := requestFallback.Add(1)
	return strconv.FormatInt(time.Now().UnixNano(), 16) + strconv.FormatUint(counter, 16)
}

func bearerCandidate(request *http.Request) []byte {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 512+32 {
		return nil
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) == 0 || len(parts[1]) > 512 {
		return nil
	}
	return []byte(parts[1])
}

func allowedRequestHost(raw string, allowed map[string]struct{}) bool {
	host, ok := hostWithoutPort(raw)
	if !ok {
		return false
	}
	_, ok = allowed[host]
	return ok
}

func hostWithoutPort(raw string) (string, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || strings.ContainsAny(raw, " /\\@,") {
		return "", false
	}
	var host string
	if strings.HasPrefix(raw, "[") {
		closing := strings.IndexByte(raw, ']')
		if closing < 0 {
			return "", false
		}
		host = raw[1:closing]
		rest := raw[closing+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || !validPort(rest[1:]) {
				return "", false
			}
		}
	} else if strings.Count(raw, ":") == 1 {
		var port string
		host, port, _ = strings.Cut(raw, ":")
		if host == "" || !validPort(port) {
			return "", false
		}
	} else if strings.Contains(raw, ":") {
		return "", false
	} else {
		host = raw
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String(), true
	}
	if host == "" || len(host) > 253 {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", false
			}
		}
	}
	return host, true
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65_535
}

func clientIP(request *http.Request, trusted map[netip.Addr]struct{}) string {
	remote, ok := parseRemoteAddr(request.RemoteAddr)
	if !ok {
		return "unknown"
	}
	if _, trustedRemote := trusted[remote]; !trustedRemote {
		return remote.String()
	}
	if values := request.Header.Values("X-Forwarded-For"); len(values) > 0 {
		if len(values) != 1 || len(values[0]) > 1_024 {
			return "unknown"
		}
		parts := strings.Split(values[0], ",")
		if len(parts) > 32 {
			return "unknown"
		}
		addresses := make([]netip.Addr, 0, len(parts))
		for _, part := range parts {
			addr, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil {
				return "unknown"
			}
			addresses = append(addresses, addr.Unmap())
		}
		for i := len(addresses) - 1; i >= 0; i-- {
			if _, isTrusted := trusted[addresses[i]]; !isTrusted {
				return addresses[i].String()
			}
		}
		if len(addresses) > 0 {
			return addresses[0].String()
		}
	}
	return remote.String()
}

func parseRemoteAddr(value string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = value
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
