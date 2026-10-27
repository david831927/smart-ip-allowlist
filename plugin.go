package smartipallowlist

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var defaultIPHeaders = []string{
	"X-Forwarded-For",
	"X-Real-Ip",
}

// 当 privateSubnets 未配置或为空数组时使用这些默认值。
var defaultPrivateSubnets = []string{
	"10.0.0.0/8",
	"100.64.0.0/10",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"198.18.0.0/15",
}

// Config 定义中间件配置。
type Config struct {
	// SourceRange 包含允许的 IP 地址或 CIDR 网段。
	SourceRange []string `json:"sourceRange,omitempty"`

	// IPHeaders 按顺序检查。每个请求头值均可包含逗号分隔的地址；
	// 同名请求头出现多次时会拒绝请求，以避免来源歧义。
	// 未配置或为空时，按 X-Forwarded-For、X-Real-Ip 的顺序检查。
	IPHeaders []string `json:"ipHeaders,omitempty"`

	// PrivateSubnets 在首次扫描请求头时跳过。
	// 未配置或为空数组时使用内置默认值。
	PrivateSubnets []string `json:"privateSubnets,omitempty"`

	// HeadersForce 启用第二次扫描，同时接受私有 IP。
	HeadersForce bool `json:"headersForce,omitempty"`

	// RejectStatusCode 默认为 403。
	RejectStatusCode int `json:"rejectStatusCode,omitempty"`

	// Debug 控制是否将请求处理结果写入标准错误输出。
	Debug bool `json:"debug,omitempty"`
}

// CreateConfig 创建插件默认配置。
func CreateConfig() *Config {
	return &Config{
		IPHeaders:        append([]string(nil), defaultIPHeaders...),
		PrivateSubnets:   append([]string(nil), defaultPrivateSubnets...),
		RejectStatusCode: http.StatusForbidden,
	}
}

type IPAllowList struct {
	next             http.Handler
	name             string
	allowedChecker   *ipChecker
	privateChecker   *ipChecker
	ipHeaders        []string
	headersForce     bool
	rejectStatusCode int
	debug            bool
}

// ipChecker 用于检查 IP 是否与单独 IP 或 CIDR 网段匹配。
type ipChecker struct {
	allowedIPs      []net.IP
	allowedNetworks []*net.IPNet
}

// New 创建中间件。
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if next == nil {
		return nil, fmt.Errorf("plugin %s: next handler is nil", name)
	}
	if config == nil {
		return nil, fmt.Errorf("plugin %s: config is nil", name)
	}

	statusCode := config.RejectStatusCode
	if statusCode == 0 {
		statusCode = http.StatusForbidden
	}
	if statusCode < 400 || statusCode > 599 {
		return nil, fmt.Errorf("plugin %s: invalid rejectStatusCode %d", name, statusCode)
	}

	allowed, err := newIPChecker(config.SourceRange)
	if err != nil {
		return nil, fmt.Errorf("plugin %s: sourceRange: %w", name, err)
	}
	if allowed.empty() {
		return nil, fmt.Errorf("plugin %s: sourceRange must not be empty", name)
	}

	privateSubnets := config.PrivateSubnets
	if len(privateSubnets) == 0 {
		privateSubnets = defaultPrivateSubnets
	}
	private, err := newIPChecker(privateSubnets)
	if err != nil {
		return nil, fmt.Errorf("plugin %s: privateSubnets: %w", name, err)
	}

	headers := config.IPHeaders
	if len(headers) == 0 {
		headers = defaultIPHeaders
	}
	normalizedHeaders := make([]string, 0, len(headers))
	for _, header := range headers {
		header = http.CanonicalHeaderKey(strings.TrimSpace(header))
		if header != "" {
			normalizedHeaders = append(normalizedHeaders, header)
		}
	}
	if len(headers) > 0 && len(normalizedHeaders) == 0 {
		return nil, fmt.Errorf("plugin %s: ipHeaders must not be empty", name)
	}

	return &IPAllowList{
		next:             next,
		name:             name,
		allowedChecker:   allowed,
		privateChecker:   private,
		ipHeaders:        normalizedHeaders,
		headersForce:     config.HeadersForce,
		rejectStatusCode: statusCode,
		debug:            config.Debug,
	}, nil
}

func (m *IPAllowList) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP, err := m.getClientIP(req)
	parsedIP := net.ParseIP(clientIP)

	if err != nil || parsedIP == nil || !m.allowedChecker.contains(parsedIP) {
		if m.debug {
			fmt.Fprintf(os.Stderr, "DEBUG smart-ip-allowlist: Rejecting IP %s\\n", clientIP)
		}
		http.Error(rw, http.StatusText(m.rejectStatusCode), m.rejectStatusCode)
		return
	}

	if m.debug {
		fmt.Fprintf(os.Stderr, "DEBUG smart-ip-allowlist: Accepting IP %s\\n", clientIP)
	}
	m.next.ServeHTTP(rw, req)
}

// getClientIP 按顺序尝试配置的请求头，首次扫描时跳过非全局单播地址和配置的私有网段。
// 可选的第二次扫描会接受私有地址，最后回退到 RemoteAddr。重复请求头会返回错误。
func (m *IPAllowList) getClientIP(req *http.Request) (string, error) {
	for _, header := range m.ipHeaders {
		if len(req.Header.Values(header)) > 1 {
			return "", fmt.Errorf("multiple %s headers", header)
		}
	}

	for _, header := range m.ipHeaders {
		values := req.Header.Values(header)
		for _, value := range values {
			for _, raw := range strings.Split(value, ",") {
				ip := parseIPValue(raw)
				if ip == "" {
					continue
				}

				parsed := net.ParseIP(ip)
				if parsed == nil || !parsed.IsGlobalUnicast() || m.privateChecker.contains(parsed) {
					continue
				}
				return ip, nil
			}
		}
	}

	if m.headersForce {
		for _, header := range m.ipHeaders {
			values := req.Header.Values(header)
			for _, value := range values {
				for _, raw := range strings.Split(value, ",") {
					if ip := parseIPValue(raw); ip != "" {
						return ip, nil
					}
				}
			}
		}
	}

	return parseIPValue(req.RemoteAddr), nil
}

// parseIPValue 接受裸 IPv4/IPv6 地址，或带端口的 IP 地址。
func parseIPValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}

	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return ""
	}
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// newIPChecker 根据单独 IP 和 CIDR 网段创建检查器。
func newIPChecker(values []string) (*ipChecker, error) {
	checker := &ipChecker{
		allowedIPs:      make([]net.IP, 0, len(values)),
		allowedNetworks: make([]*net.IPNet, 0, len(values)),
	}

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("invalid IP or CIDR %q", value)
		}

		if ip := net.ParseIP(value); ip != nil {
			checker.allowedIPs = append(checker.allowedIPs, ip)
			continue
		}

		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", value)
		}
		checker.allowedNetworks = append(checker.allowedNetworks, network)
	}

	return checker, nil
}

func (c *ipChecker) empty() bool {
	return len(c.allowedIPs) == 0 && len(c.allowedNetworks) == 0
}

func (c *ipChecker) contains(ip net.IP) bool {
	for _, allowedIP := range c.allowedIPs {
		if allowedIP.Equal(ip) {
			return true
		}
	}

	for _, network := range c.allowedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
