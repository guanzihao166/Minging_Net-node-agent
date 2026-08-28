package agentprotocol

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const SchemaVersion = 1

type Protocol string

const (
	ProtocolVLESS        Protocol = "vless"
	ProtocolVMess        Protocol = "vmess"
	ProtocolTrojan       Protocol = "trojan"
	ProtocolSS2022       Protocol = "shadowsocks2022"
	ProtocolTUIC         Protocol = "tuic"
	ProtocolHysteria2    Protocol = "hysteria2"
	SecurityNone                  = "none"
	SecurityTLS                   = "tls"
	SecurityReality               = "reality"
	TransportTCP                  = "tcp"
	TransportWebSocket            = "ws"
	TransportGRPC                 = "grpc"
	TransportHTTPUpgrade          = "httpupgrade"
	TransportXHTTP                = "xhttp"
	TransportSplitHTTP            = "splithttp"
	TransportQUIC                 = "quic"
)

type DesiredConfig struct {
	SchemaVersion int               `json:"schema_version"`
	Version       uint64            `json:"version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	AgentNodeID   int64             `json:"agent_node_id"`
	Inbounds      []Inbound         `json:"inbounds"`
	Security      []SecurityProfile `json:"security_profiles,omitempty"`
	Routing       RoutingConfig     `json:"routing"`
}

type RoutingConfig struct {
	DNSProfile      string `json:"dns_profile,omitempty"`
	BlockProfile    string `json:"block_profile,omitempty"`
	OutboundProfile string `json:"outbound_profile,omitempty"`
}

type Inbound struct {
	ID                     int64            `json:"id"`
	Name                   string           `json:"name"`
	Protocol               Protocol         `json:"protocol"`
	Listen                 string           `json:"listen"`
	Port                   int              `json:"port"`
	Network                string           `json:"network"`
	Enabled                bool             `json:"enabled"`
	Transport              Transport        `json:"transport"`
	SecurityProfileID      int64            `json:"security_profile_id,omitempty"`
	TrafficMultiplierMilli int64            `json:"traffic_multiplier_milli"`
	VLESS                  *VLESSConfig     `json:"vless,omitempty"`
	VMess                  *VMessConfig     `json:"vmess,omitempty"`
	Trojan                 *TrojanConfig    `json:"trojan,omitempty"`
	SS2022                 *SS2022Config    `json:"shadowsocks2022,omitempty"`
	TUIC                   *TUICConfig      `json:"tuic,omitempty"`
	Hysteria2              *Hysteria2Config `json:"hysteria2,omitempty"`
}

type Transport struct {
	Type                string `json:"type"`
	Path                string `json:"path,omitempty"`
	Host                string `json:"host,omitempty"`
	ServiceName         string `json:"service_name,omitempty"`
	XHTTPMode           string `json:"xhttp_mode,omitempty"`
	XHTTPExtra          string `json:"xhttp_extra,omitempty"`
	AcceptProxyProtocol bool   `json:"accept_proxy_protocol,omitempty"`
}

type SecurityProfile struct {
	ID      int64           `json:"id"`
	Name    string          `json:"name"`
	Type    string          `json:"type"`
	TLS     *TLSProfile     `json:"tls,omitempty"`
	Reality *RealityProfile `json:"reality,omitempty"`
}

type TLSProfile struct {
	ServerNames    []string `json:"server_names"`
	CertificateRef string   `json:"certificate_ref"`
	PrivateKeyRef  string   `json:"private_key_ref"`
	MinVersion     string   `json:"min_version,omitempty"`
	MaxVersion     string   `json:"max_version,omitempty"`
	ALPN           []string `json:"alpn,omitempty"`
}

type RealityProfile struct {
	ServerNames   []string `json:"server_names"`
	Destination   string   `json:"destination"`
	PrivateKeyRef string   `json:"private_key_ref"`
	PublicKey     string   `json:"public_key"`
	ShortIDs      []string `json:"short_ids"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	SpiderX       string   `json:"spider_x,omitempty"`
}

type VLESSConfig struct {
	Decryption              string `json:"decryption"`
	Flow                    string `json:"flow,omitempty"`
	EncryptionMode          string `json:"encryption_mode,omitempty"`
	EncryptionTicket        string `json:"encryption_ticket,omitempty"`
	EncryptionServerPadding string `json:"encryption_server_padding,omitempty"`
	EncryptionClientRTT     string `json:"encryption_client_rtt,omitempty"`
	EncryptionPrivateKeyRef string `json:"encryption_private_key_ref,omitempty"`
	EncryptionClientConfig  string `json:"encryption_client_config,omitempty"`
}

// VMess is intentionally fixed to UUID authentication with alterId 0 and
// automatic cipher selection. The transport and TLS profile live on Inbound.
type VMessConfig struct{}

type TrojanConfig struct{}

type SS2022Config struct {
	Method       string `json:"method"`
	ServerKeyRef string `json:"server_key_ref"`
	Network      string `json:"network"`
}

type TUICConfig struct {
	Version           int    `json:"version"`
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
	HeartbeatSeconds  int    `json:"heartbeat_seconds"`
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`
}

type Hysteria2Config struct {
	UpMbps             int    `json:"up_mbps"`
	DownMbps           int    `json:"down_mbps"`
	Obfs               string `json:"obfs,omitempty"`
	ObfsPasswordRef    string `json:"obfs_password_ref,omitempty"`
	HopPorts           string `json:"hop_ports,omitempty"`
	HopIntervalSeconds int    `json:"hop_interval_seconds,omitempty"`
}

var (
	secretRefPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*:[0-9]+:[0-9]+$`)
	hostNamePattern  = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
)

func ValidateDesiredConfig(config DesiredConfig) error {
	if config.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema version %d", config.SchemaVersion)
	}
	if config.Version == 0 || config.AgentNodeID <= 0 {
		return errors.New("config version and agent node id are required")
	}
	profiles := make(map[int64]SecurityProfile, len(config.Security))
	for _, profile := range config.Security {
		if profile.ID <= 0 {
			return errors.New("security profile id is required")
		}
		if _, exists := profiles[profile.ID]; exists {
			return fmt.Errorf("duplicate security profile %d", profile.ID)
		}
		if err := validateSecurityProfile(profile); err != nil {
			return fmt.Errorf("security profile %d: %w", profile.ID, err)
		}
		profiles[profile.ID] = profile
	}
	ports := make(map[string]int64)
	ids := make(map[int64]struct{})
	for _, inbound := range config.Inbounds {
		if inbound.ID <= 0 {
			return errors.New("inbound id is required")
		}
		if _, exists := ids[inbound.ID]; exists {
			return fmt.Errorf("duplicate inbound id %d", inbound.ID)
		}
		ids[inbound.ID] = struct{}{}
		if inbound.Port <= 0 || inbound.Port > 65535 {
			return fmt.Errorf("inbound %d has invalid port", inbound.ID)
		}
		listen := strings.TrimSpace(inbound.Listen)
		if listen != "0.0.0.0" && listen != "::" && net.ParseIP(listen) == nil {
			return fmt.Errorf("inbound %d has invalid listen address", inbound.ID)
		}
		key := strings.ToLower(inbound.Network) + "|" + listen + "|" + strconv.Itoa(inbound.Port)
		if previous, exists := ports[key]; exists {
			return fmt.Errorf("inbound %d conflicts with inbound %d", inbound.ID, previous)
		}
		ports[key] = inbound.ID
		profile, hasProfile := profiles[inbound.SecurityProfileID]
		if err := validateInbound(inbound, profile, hasProfile); err != nil {
			return fmt.Errorf("inbound %d: %w", inbound.ID, err)
		}
	}
	return nil
}

func ReferencedSecretRefs(config DesiredConfig) []string {
	seen := make(map[string]struct{})
	refs := make([]string, 0)
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		if _, exists := seen[ref]; exists {
			return
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	for _, profile := range config.Security {
		if profile.TLS != nil {
			add(profile.TLS.CertificateRef)
			add(profile.TLS.PrivateKeyRef)
		}
		if profile.Reality != nil {
			add(profile.Reality.PrivateKeyRef)
		}
	}
	for _, inbound := range config.Inbounds {
		if inbound.VLESS != nil {
			add(inbound.VLESS.EncryptionPrivateKeyRef)
		}
		if inbound.SS2022 != nil {
			add(inbound.SS2022.ServerKeyRef)
		}
		if inbound.Hysteria2 != nil {
			add(inbound.Hysteria2.ObfsPasswordRef)
		}
	}
	sort.Strings(refs)
	return refs
}

func validateSecurityProfile(profile SecurityProfile) error {
	switch profile.Type {
	case SecurityTLS:
		if profile.TLS == nil || profile.Reality != nil {
			return errors.New("tls profile payload is invalid")
		}
		if err := validateServerNames(profile.TLS.ServerNames); err != nil {
			return err
		}
		if !validSecretRef(profile.TLS.CertificateRef) || !validSecretRef(profile.TLS.PrivateKeyRef) {
			return errors.New("tls certificate and private key references are required")
		}
		if profile.TLS.MinVersion != "" && profile.TLS.MinVersion != "1.2" && profile.TLS.MinVersion != "1.3" {
			return errors.New("tls minimum version is invalid")
		}
		if profile.TLS.MaxVersion != "" && profile.TLS.MaxVersion != "1.2" && profile.TLS.MaxVersion != "1.3" {
			return errors.New("tls maximum version is invalid")
		}
	case SecurityReality:
		if profile.Reality == nil || profile.TLS != nil {
			return errors.New("reality profile payload is invalid")
		}
		if err := validateReality(*profile.Reality); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported security profile type %q", profile.Type)
	}
	return nil
}

func validateReality(profile RealityProfile) error {
	if err := validateServerNames(profile.ServerNames); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(profile.Destination))
	if err != nil || host == "" {
		return errors.New("reality destination must be host:port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber <= 0 || portNumber > 65535 {
		return errors.New("reality destination port is invalid")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsPrivate()) {
		return errors.New("reality destination is private or reserved")
	}
	if !validSecretRef(profile.PrivateKeyRef) || strings.TrimSpace(profile.PublicKey) == "" {
		return errors.New("reality key references are required")
	}
	if len(profile.ShortIDs) == 0 || len(profile.ShortIDs) > 8 {
		return errors.New("reality requires one to eight short ids")
	}
	seen := make(map[string]struct{}, len(profile.ShortIDs))
	for _, shortID := range profile.ShortIDs {
		shortID = strings.ToLower(strings.TrimSpace(shortID))
		if len(shortID) == 0 || len(shortID) > 16 || len(shortID)%2 != 0 {
			return errors.New("reality short id has invalid length")
		}
		if _, err := hex.DecodeString(shortID); err != nil {
			return errors.New("reality short id is not hexadecimal")
		}
		if _, exists := seen[shortID]; exists {
			return errors.New("reality short id is duplicated")
		}
		seen[shortID] = struct{}{}
	}
	return nil
}

func validateInbound(inbound Inbound, profile SecurityProfile, hasProfile bool) error {
	if inbound.TrafficMultiplierMilli <= 0 || inbound.TrafficMultiplierMilli > 100000 {
		return errors.New("traffic multiplier is outside 0.001x..100x")
	}
	if err := validateProxyProtocol(inbound); err != nil {
		return err
	}
	switch inbound.Protocol {
	case ProtocolVLESS:
		return validateVLESS(inbound, profile, hasProfile)
	case ProtocolVMess:
		return validateVMess(inbound, profile, hasProfile)
	case ProtocolTrojan:
		return validateTrojan(inbound, profile, hasProfile)
	case ProtocolSS2022:
		return validateSS2022(inbound, hasProfile)
	case ProtocolTUIC:
		return validateTUIC(inbound, profile, hasProfile)
	case ProtocolHysteria2:
		return validateHysteria2(inbound, profile, hasProfile)
	default:
		return fmt.Errorf("unsupported protocol %q", inbound.Protocol)
	}
}

func validateProxyProtocol(inbound Inbound) error {
	if !inbound.Transport.AcceptProxyProtocol {
		return nil
	}
	if inbound.Transport.Type != TransportTCP && inbound.Transport.Type != TransportWebSocket {
		return errors.New("proxy protocol requires tcp or websocket transport")
	}
	if inbound.Protocol == ProtocolSS2022 && (inbound.SS2022 == nil || inbound.SS2022.Network != "tcp") {
		return errors.New("proxy protocol requires shadowsocks2022 tcp-only network")
	}
	return nil
}

func validateVLESS(inbound Inbound, profile SecurityProfile, hasProfile bool) error {
	if inbound.VLESS == nil || inbound.VMess != nil || inbound.Trojan != nil || inbound.SS2022 != nil || inbound.TUIC != nil || inbound.Hysteria2 != nil {
		return errors.New("vless protocol payload is invalid")
	}
	if !hasProfile || profile.Type != SecurityTLS && profile.Type != SecurityReality {
		return errors.New("vless requires tls or reality")
	}
	if err := validateVLESSEncryption(*inbound.VLESS); err != nil {
		return err
	}
	if err := validateStreamTransport(inbound.Transport); err != nil {
		return err
	}
	if profile.Type == SecurityReality && !supportsRealityTransport(inbound.Transport.Type) {
		return errors.New("vless reality supports tcp, grpc, xhttp, or splithttp transport")
	}
	if inbound.VLESS.Flow != "" && inbound.VLESS.Flow != "xtls-rprx-vision" {
		return errors.New("vless flow is invalid")
	}
	return nil
}

func supportsRealityTransport(transport string) bool {
	switch transport {
	case TransportTCP, TransportGRPC, TransportXHTTP, TransportSplitHTTP:
		return true
	default:
		return false
	}
}

func validateVLESSEncryption(config VLESSConfig) error {
	switch config.Decryption {
	case "none":
		if config.EncryptionMode != "" || config.EncryptionTicket != "" || config.EncryptionServerPadding != "" || config.EncryptionClientRTT != "" || config.EncryptionPrivateKeyRef != "" || config.EncryptionClientConfig != "" {
			return errors.New("vless encryption fields require mlkem768x25519plus")
		}
	case "mlkem768x25519plus":
		switch config.EncryptionMode {
		case "native", "xorpub", "random":
		default:
			return errors.New("vless encryption mode is invalid")
		}
		if !validSecretRef(config.EncryptionPrivateKeyRef) {
			return errors.New("vless encryption private key reference is required")
		}
		if config.EncryptionClientRTT != "0rtt" && config.EncryptionClientRTT != "1rtt" {
			return errors.New("vless encryption client rtt is invalid")
		}
		if !validVLESSServerTicket(config.EncryptionTicket) || !validVLESSEncryptionConfig(config.EncryptionClientConfig, true) {
			return errors.New("vless encryption configuration is invalid")
		}
	default:
		return errors.New("unsupported vless decryption")
	}
	return nil
}

func validVLESSEncryptionConfig(value string, client bool) bool {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" || (parts[1] != "native" && parts[1] != "xorpub" && parts[1] != "random") {
		return false
	}
	return client && (parts[2] == "0rtt" || parts[2] == "1rtt")
}

func validVLESSServerTicket(value string) bool {
	value = strings.TrimSuffix(strings.TrimSpace(value), "s")
	parts := strings.Split(value, "-")
	if len(parts) == 0 || len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		seconds, err := strconv.Atoi(part)
		if err != nil || seconds <= 0 || seconds > 86400 {
			return false
		}
	}
	return true
}

func validateVMess(inbound Inbound, profile SecurityProfile, hasProfile bool) error {
	if inbound.VMess == nil || inbound.VLESS != nil || inbound.Trojan != nil || inbound.SS2022 != nil || inbound.TUIC != nil || inbound.Hysteria2 != nil {
		return errors.New("vmess protocol payload is invalid")
	}
	if hasProfile && profile.Type != SecurityTLS {
		return errors.New("vmess only supports tls or no security profile")
	}
	return validateStreamTransport(inbound.Transport)
}

func validateTrojan(inbound Inbound, profile SecurityProfile, hasProfile bool) error {
	if inbound.Trojan == nil || inbound.VLESS != nil || inbound.VMess != nil || inbound.SS2022 != nil || inbound.TUIC != nil || inbound.Hysteria2 != nil {
		return errors.New("trojan protocol payload is invalid")
	}
	if !hasProfile || profile.Type != SecurityTLS {
		return errors.New("trojan requires tls")
	}
	return validateStreamTransport(inbound.Transport)
}

func validateSS2022(inbound Inbound, hasProfile bool) error {
	if inbound.SS2022 == nil || inbound.VLESS != nil || inbound.VMess != nil || inbound.Trojan != nil || inbound.TUIC != nil || inbound.Hysteria2 != nil {
		return errors.New("shadowsocks2022 protocol payload is invalid")
	}
	if hasProfile || inbound.SecurityProfileID != 0 {
		return errors.New("shadowsocks2022 does not use tls or reality")
	}
	switch inbound.SS2022.Method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
	default:
		return errors.New("unsupported shadowsocks2022 method")
	}
	if !validSecretRef(inbound.SS2022.ServerKeyRef) {
		return errors.New("shadowsocks2022 server key reference is required")
	}
	if inbound.SS2022.Network != "tcp" && inbound.SS2022.Network != "udp" && inbound.SS2022.Network != "tcp,udp" {
		return errors.New("shadowsocks2022 network is invalid")
	}
	if inbound.Transport.Type != "" && inbound.Transport.Type != TransportTCP {
		return errors.New("shadowsocks2022 transport is invalid")
	}
	return nil
}

func validateTUIC(inbound Inbound, profile SecurityProfile, hasProfile bool) error {
	if inbound.TUIC == nil || inbound.VLESS != nil || inbound.VMess != nil || inbound.Trojan != nil || inbound.SS2022 != nil || inbound.Hysteria2 != nil {
		return errors.New("tuic protocol payload is invalid")
	}
	if !hasProfile || profile.Type != SecurityTLS {
		return errors.New("tuic requires tls")
	}
	if inbound.Network != "udp" || inbound.Transport.Type != TransportQUIC {
		return errors.New("tuic requires udp/quic")
	}
	if inbound.TUIC.Version != 5 {
		return errors.New("tuic version must be 5")
	}
	switch inbound.TUIC.CongestionControl {
	case "bbr", "cubic", "new_reno":
	default:
		return errors.New("tuic congestion control is invalid")
	}
	if inbound.TUIC.HeartbeatSeconds < 1 || inbound.TUIC.HeartbeatSeconds > 300 {
		return errors.New("tuic heartbeat is invalid")
	}
	return nil
}

func validateHysteria2(inbound Inbound, profile SecurityProfile, hasProfile bool) error {
	if inbound.Hysteria2 == nil || inbound.VLESS != nil || inbound.VMess != nil || inbound.Trojan != nil || inbound.SS2022 != nil || inbound.TUIC != nil {
		return errors.New("hysteria2 protocol payload is invalid")
	}
	if !hasProfile || profile.Type != SecurityTLS {
		return errors.New("hysteria2 requires tls")
	}
	if inbound.Network != "udp" || inbound.Transport.Type != TransportQUIC {
		return errors.New("hysteria2 requires udp/quic")
	}
	if inbound.Hysteria2.UpMbps <= 0 || inbound.Hysteria2.DownMbps <= 0 {
		return errors.New("hysteria2 bandwidth is required")
	}
	if inbound.Hysteria2.Obfs != "" && inbound.Hysteria2.Obfs != "salamander" {
		return errors.New("hysteria2 obfs is invalid")
	}
	if inbound.Hysteria2.Obfs == "salamander" && !validSecretRef(inbound.Hysteria2.ObfsPasswordRef) {
		return errors.New("hysteria2 salamander secret reference is required")
	}
	if inbound.Hysteria2.HopPorts != "" {
		if err := validatePortRange(inbound.Hysteria2.HopPorts); err != nil {
			return err
		}
		if inbound.Hysteria2.HopIntervalSeconds < 5 || inbound.Hysteria2.HopIntervalSeconds > 3600 {
			return errors.New("hysteria2 hop interval is invalid")
		}
	}
	return nil
}

func validateStreamTransport(transport Transport) error {
	switch transport.Type {
	case TransportTCP:
		if transport.Path != "" || transport.ServiceName != "" || transport.XHTTPMode != "" || transport.XHTTPExtra != "" {
			return errors.New("tcp transport has incompatible fields")
		}
	case TransportWebSocket:
		if !strings.HasPrefix(transport.Path, "/") {
			return errors.New("websocket path must start with slash")
		}
	case TransportGRPC:
		if strings.TrimSpace(transport.ServiceName) == "" || strings.ContainsAny(transport.ServiceName, "\r\n") {
			return errors.New("grpc service name is required")
		}
	case TransportHTTPUpgrade:
		if !strings.HasPrefix(transport.Path, "/") {
			return errors.New("httpupgrade path must start with slash")
		}
	case TransportXHTTP, TransportSplitHTTP:
		if !strings.HasPrefix(transport.Path, "/") {
			return errors.New("xhttp path must start with slash")
		}
		if strings.TrimSpace(transport.XHTTPMode) == "" || strings.ContainsAny(transport.XHTTPMode, "\r\n") {
			return errors.New("xhttp mode is required")
		}
		if strings.TrimSpace(transport.XHTTPExtra) != "" && !json.Valid([]byte(transport.XHTTPExtra)) {
			return errors.New("xhttp extra must be valid json")
		}
	default:
		return errors.New("unsupported stream transport")
	}
	return nil
}

func validateServerNames(names []string) error {
	if len(names) == 0 || len(names) > 16 {
		return errors.New("one to sixteen server names are required")
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if net.ParseIP(name) == nil && !hostNamePattern.MatchString(name) {
			return fmt.Errorf("invalid server name %q", name)
		}
	}
	return nil
}

func validatePortRange(value string) error {
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return errors.New("port range must be start-end")
	}
	start, errStart := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, errEnd := strconv.Atoi(strings.TrimSpace(parts[1]))
	if errStart != nil || errEnd != nil || start <= 0 || end > 65535 || end < start || end-start > 1000 {
		return errors.New("port range is invalid or too large")
	}
	return nil
}

func validSecretRef(value string) bool {
	return secretRefPattern.MatchString(strings.TrimSpace(value))
}
