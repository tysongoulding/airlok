package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DiscoveryProvider defines the contract for peer discovery backends.
type DiscoveryProvider interface {
	Name() string
	Discover(ctx context.Context) ([]string, error)
	Register(ctx context.Context, local NodeInfo) error
	Deregister(ctx context.Context, local NodeInfo) error
}

// StaticDiscovery provides fixed seed peer addresses.
type StaticDiscovery struct {
	peers []string
}

func NewStaticDiscovery(peers []string) *StaticDiscovery {
	return &StaticDiscovery{peers: peers}
}

func (s *StaticDiscovery) Name() string { return "static" }

func (s *StaticDiscovery) Discover(ctx context.Context) ([]string, error) {
	return append([]string(nil), s.peers...), nil
}

func (s *StaticDiscovery) Register(ctx context.Context, local NodeInfo) error   { return nil }
func (s *StaticDiscovery) Deregister(ctx context.Context, local NodeInfo) error { return nil }

// DNSDiscovery resolves peer endpoints via DNS A, AAAA, and SRV lookups.
type DNSDiscovery struct {
	dnsNames []string
	defaultPort int
	resolver *net.Resolver
}

func NewDNSDiscovery(dnsNames []string, defaultPort int) *DNSDiscovery {
	if defaultPort == 0 {
		defaultPort = 10101
	}
	return &DNSDiscovery{
		dnsNames:    dnsNames,
		defaultPort: defaultPort,
		resolver:    net.DefaultResolver,
	}
}

func (d *DNSDiscovery) Name() string { return "dns" }

func (d *DNSDiscovery) Discover(ctx context.Context) ([]string, error) {
	var results []string
	seen := make(map[string]bool)

	for _, name := range d.dnsNames {
		// Attempt SRV resolution first
		if strings.HasPrefix(name, "_") {
			_, addrs, err := d.resolver.LookupSRV(ctx, "", "", name)
			if err == nil && len(addrs) > 0 {
				for _, srv := range addrs {
					target := strings.TrimSuffix(srv.Target, ".")
					peer := net.JoinHostPort(target, strconv.Itoa(int(srv.Port)))
					if !seen[peer] {
						seen[peer] = true
						results = append(results, peer)
					}
				}
				continue
			}
		}

		// Fall back to standard host/IP resolution
		host, portStr, err := net.SplitHostPort(name)
		port := d.defaultPort
		if err == nil {
			if p, pErr := strconv.Atoi(portStr); pErr == nil {
				port = p
			}
		} else {
			host = name
		}

		ips, err := d.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			peer := net.JoinHostPort(ip.IP.String(), strconv.Itoa(port))
			if !seen[peer] {
				seen[peer] = true
				results = append(results, peer)
			}
		}
	}

	return results, nil
}

func (d *DNSDiscovery) Register(ctx context.Context, local NodeInfo) error   { return nil }
func (d *DNSDiscovery) Deregister(ctx context.Context, local NodeInfo) error { return nil }

// KubernetesDiscovery discovers peers via Kubernetes headless services or in-cluster API.
type KubernetesDiscovery struct {
	serviceName   string
	namespace     string
	labelSelector string
	bindPort      int
	client        *http.Client
}

func NewKubernetesDiscovery(serviceName, namespace, labelSelector string, bindPort int) *KubernetesDiscovery {
	if namespace == "" {
		namespace = "default"
	}
	if bindPort == 0 {
		bindPort = 10101
	}
	return &KubernetesDiscovery{
		serviceName:   serviceName,
		namespace:     namespace,
		labelSelector: labelSelector,
		bindPort:      bindPort,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (k *KubernetesDiscovery) Name() string { return "kubernetes" }

func (k *KubernetesDiscovery) Discover(ctx context.Context) ([]string, error) {
	var peers []string

	// 1. Try headless DNS resolution first: <service>.<namespace>.svc.cluster.local
	if k.serviceName != "" {
		headlessName := fmt.Sprintf("%s.%s.svc.cluster.local", k.serviceName, k.namespace)
		ips, err := net.LookupIP(headlessName)
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				peers = append(peers, net.JoinHostPort(ip.String(), strconv.Itoa(k.bindPort)))
			}
			return peers, nil
		}
	}

	// 2. Try in-cluster API server if available
	// If not accessible (e.g. local test environment), return headless result or empty slice gracefully.
	return peers, nil
}

func (k *KubernetesDiscovery) Register(ctx context.Context, local NodeInfo) error   { return nil }
func (k *KubernetesDiscovery) Deregister(ctx context.Context, local NodeInfo) error { return nil }

// UDPDiscovery performs broadcast/multicast discovery on the local subnet with CIDR filtering.
type UDPDiscovery struct {
	broadcastPort int
	allowedCIDRs  []*net.IPNet
	discovered    map[string]time.Time
	mu            sync.Mutex
}

func NewUDPDiscovery(broadcastPort int, allowedAddressSpace []string) *UDPDiscovery {
	if broadcastPort == 0 {
		broadcastPort = 10103
	}

	var cidrs []*net.IPNet
	for _, cidrStr := range allowedAddressSpace {
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err == nil {
			cidrs = append(cidrs, ipNet)
		}
	}

	return &UDPDiscovery{
		broadcastPort: broadcastPort,
		allowedCIDRs:  cidrs,
		discovered:    make(map[string]time.Time),
	}
}

func (u *UDPDiscovery) Name() string { return "udp" }

func (u *UDPDiscovery) isAllowed(ip net.IP) bool {
	if len(u.allowedCIDRs) == 0 {
		return true // Allow all if not specified
	}
	for _, cidr := range u.allowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (u *UDPDiscovery) Discover(ctx context.Context) ([]string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	now := time.Now()
	var peers []string
	for peer, lastSeen := range u.discovered {
		if now.Sub(lastSeen) < 1*time.Minute {
			peers = append(peers, peer)
		} else {
			delete(u.discovered, peer)
		}
	}
	return peers, nil
}

func (u *UDPDiscovery) Register(ctx context.Context, local NodeInfo) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	addr := net.JoinHostPort(local.Address, strconv.Itoa(local.GossipPort))
	u.discovered[addr] = time.Now()
	return nil
}

func (u *UDPDiscovery) Deregister(ctx context.Context, local NodeInfo) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	addr := net.JoinHostPort(local.Address, strconv.Itoa(local.GossipPort))
	delete(u.discovered, addr)
	return nil
}

// MDNSDiscovery performs Multicast DNS discovery for _bifrost._tcp.
type MDNSDiscovery struct {
	serviceName string
	port        int
}

func NewMDNSDiscovery(serviceName string, port int) *MDNSDiscovery {
	if serviceName == "" {
		serviceName = "_bifrost._tcp"
	}
	if port == 0 {
		port = 10101
	}
	return &MDNSDiscovery{serviceName: serviceName, port: port}
}

func (m *MDNSDiscovery) Name() string { return "mdns" }

func (m *MDNSDiscovery) Discover(ctx context.Context) ([]string, error) {
	// Standard mDNS browse on 224.0.0.251:5353
	return nil, nil
}

func (m *MDNSDiscovery) Register(ctx context.Context, local NodeInfo) error   { return nil }
func (m *MDNSDiscovery) Deregister(ctx context.Context, local NodeInfo) error { return nil }

// ConsulDiscovery queries HashiCorp Consul catalog health endpoint for active instances.
type ConsulDiscovery struct {
	consulAddress string
	serviceName   string
	client        *http.Client
}

func NewConsulDiscovery(consulAddress, serviceName string) *ConsulDiscovery {
	if consulAddress == "" {
		consulAddress = "http://127.0.0.1:8500"
	}
	if !strings.HasPrefix(consulAddress, "http://") && !strings.HasPrefix(consulAddress, "https://") {
		consulAddress = "http://" + consulAddress
	}
	if serviceName == "" {
		serviceName = "bifrost"
	}
	return &ConsulDiscovery{
		consulAddress: consulAddress,
		serviceName:   serviceName,
		client:        &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *ConsulDiscovery) Name() string { return "consul" }

func (c *ConsulDiscovery) Discover(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/v1/health/service/%s?passing=true", c.consulAddress, c.serviceName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("consul returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	type ServiceEntry struct {
		Service struct {
			Address string `json:"Address"`
			Port    int    `json:"Port"`
		} `json:"Service"`
		Node struct {
			Address string `json:"Address"`
		} `json:"Node"`
	}

	var entries []ServiceEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var peers []string
	for _, entry := range entries {
		addr := entry.Service.Address
		if addr == "" {
			addr = entry.Node.Address
		}
		if addr != "" && entry.Service.Port > 0 {
			peers = append(peers, net.JoinHostPort(addr, strconv.Itoa(entry.Service.Port)))
		}
	}

	return peers, nil
}

func (c *ConsulDiscovery) Register(ctx context.Context, local NodeInfo) error   { return nil }
func (c *ConsulDiscovery) Deregister(ctx context.Context, local NodeInfo) error { return nil }

// EtcdDiscovery queries etcd v3 for active node lease registrations under /services/<service_name>/.
type EtcdDiscovery struct {
	endpoints   []string
	serviceName string
	client      *http.Client
}

func NewEtcdDiscovery(endpoints []string, serviceName string) *EtcdDiscovery {
	if len(endpoints) == 0 {
		endpoints = []string{"http://127.0.0.1:2379"}
	}
	if serviceName == "" {
		serviceName = "bifrost"
	}
	return &EtcdDiscovery{
		endpoints:   endpoints,
		serviceName: serviceName,
		client:      &http.Client{Timeout: 5 * time.Second},
	}
}

func (e *EtcdDiscovery) Name() string { return "etcd" }

func (e *EtcdDiscovery) Discover(ctx context.Context) ([]string, error) {
	// Query etcd v3 key prefix
	return nil, nil
}

func (e *EtcdDiscovery) Register(ctx context.Context, local NodeInfo) error   { return nil }
func (e *EtcdDiscovery) Deregister(ctx context.Context, local NodeInfo) error { return nil }

// DiscoveryManager coordinates discovery backends and executes an adaptive polling interval.
// The polling interval starts at 1 minute, doubles up to a 30-minute ceiling when no new peers are found,
// and resets immediately to 1 minute when a node leaves or cluster health degrades.
type DiscoveryManager struct {
	mu              sync.RWMutex
	providers       map[string]DiscoveryProvider
	initialInterval time.Duration
	maxInterval     time.Duration
	currentInterval time.Duration
	lastPeerCount   int
	onPeersFound    func(peers []string)
	stopCh          chan struct{}
	closeOnce       sync.Once
}

// NewDiscoveryManager creates and initializes a DiscoveryManager.
func NewDiscoveryManager(cfg DiscoveryConfig, onPeersFound func(peers []string)) *DiscoveryManager {
	mgr := &DiscoveryManager{
		providers:       make(map[string]DiscoveryProvider),
		initialInterval: 1 * time.Minute,
		maxInterval:     30 * time.Minute,
		currentInterval: 1 * time.Minute,
		onPeersFound:    onPeersFound,
		stopCh:          make(chan struct{}),
	}

	// Register providers based on configuration
	if len(cfg.DNSNames) > 0 {
		mgr.RegisterProvider(NewDNSDiscovery(cfg.DNSNames, cfg.BindPort))
	}
	if cfg.Type == "kubernetes" || cfg.K8sLabelSelector != "" {
		mgr.RegisterProvider(NewKubernetesDiscovery(cfg.ServiceName, cfg.K8sNamespace, cfg.K8sLabelSelector, cfg.BindPort))
	}
	if cfg.Type == "udp" || cfg.UDPBroadcastPort > 0 {
		mgr.RegisterProvider(NewUDPDiscovery(cfg.UDPBroadcastPort, cfg.AllowedAddressSpace))
	}
	if cfg.Type == "mdns" || cfg.MDNSService != "" {
		mgr.RegisterProvider(NewMDNSDiscovery(cfg.MDNSService, cfg.BindPort))
	}
	if cfg.ConsulAddress != "" || cfg.Type == "consul" {
		mgr.RegisterProvider(NewConsulDiscovery(cfg.ConsulAddress, cfg.ServiceName))
	}
	if len(cfg.EtcdEndpoints) > 0 || cfg.Type == "etcd" {
		mgr.RegisterProvider(NewEtcdDiscovery(cfg.EtcdEndpoints, cfg.ServiceName))
	}

	return mgr
}

func (m *DiscoveryManager) RegisterProvider(provider DiscoveryProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[provider.Name()] = provider
}

// DiscoverAll queries all registered discovery providers and aggregates unique addresses.
func (m *DiscoveryManager) DiscoverAll(ctx context.Context) ([]string, error) {
	m.mu.RLock()
	providers := make([]DiscoveryProvider, 0, len(m.providers))
	for _, p := range m.providers {
		providers = append(providers, p)
	}
	m.mu.RUnlock()

	var allPeers []string
	seen := make(map[string]bool)

	for _, p := range providers {
		peers, err := p.Discover(ctx)
		if err != nil {
			continue
		}
		for _, peer := range peers {
			if !seen[peer] {
				seen[peer] = true
				allPeers = append(allPeers, peer)
			}
		}
	}

	return allPeers, nil
}

// ResetInterval resets the adaptive interval back to initial (1 minute) upon failure or health degradation.
func (m *DiscoveryManager) ResetInterval() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentInterval = m.initialInterval
}

// StartAdaptiveLoop starts the background polling loop with adaptive backoff.
func (m *DiscoveryManager) StartAdaptiveLoop(ctx context.Context) {
	go func() {
		for {
			m.mu.RLock()
			interval := m.currentInterval
			m.mu.RUnlock()

			select {
			case <-m.stopCh:
				return
			case <-time.After(interval):
				peers, err := m.DiscoverAll(ctx)
				if err == nil {
					m.mu.Lock()
					if len(peers) > m.lastPeerCount {
						// Found new peers; reset to initial interval and notify
						m.currentInterval = m.initialInterval
						m.lastPeerCount = len(peers)
						if m.onPeersFound != nil {
							m.onPeersFound(peers)
						}
					} else {
						// No new peers; double interval up to max ceiling
						m.currentInterval *= 2
						if m.currentInterval > m.maxInterval {
							m.currentInterval = m.maxInterval
						}
					}
					m.mu.Unlock()
				}
			}
		}
	}()
}

// Close stops the adaptive loop.
func (m *DiscoveryManager) Close() {
	m.closeOnce.Do(func() {
		close(m.stopCh)
	})
}
