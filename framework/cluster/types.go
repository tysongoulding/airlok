package cluster

import (
	"context"
	"time"
)

// ClusterMode represents the operational topology of the cluster.
type ClusterMode string

const (
	ClusterModeMesh   ClusterMode = "mesh"
	ClusterModeBroker ClusterMode = "broker"
)

// NodeState represents the health lifecycle state of a cluster member.
type NodeState string

const (
	NodeStateAlive   NodeState = "alive"
	NodeStateSuspect NodeState = "suspect"
	NodeStateDead    NodeState = "dead"
	NodeStateLeft    NodeState = "left"
)

// NodeInfo contains identity, network, and health metadata for a node.
type NodeInfo struct {
	NodeID       string            `json:"node_id"`
	Address      string            `json:"address"`
	GossipPort   int               `json:"gossip_port"`
	GRPCPort     int               `json:"grpc_port"`
	Region       string            `json:"region"`
	State        NodeState         `json:"state"`
	IsLeader     bool              `json:"is_leader"`
	IsRegLeader  bool              `json:"is_regional_leader"`
	LastSeen     time.Time         `json:"last_seen"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ClusterNode is an alias for NodeInfo complying with the ClusterCoordinator interface.
type ClusterNode = NodeInfo

// NodeMetadata is the compact serialized payload transferred via memberlist NodeMeta (max 512 bytes).
type NodeMetadata struct {
	NodeID       string            `json:"id"`
	Address      string            `json:"addr,omitempty"`
	GRPCPort     int               `json:"grpc"`
	Region       string            `json:"reg"`
	Capabilities []string          `json:"caps,omitempty"`
	Metadata     map[string]string `json:"meta,omitempty"`
}

// Config configures the cluster coordinator, gossip transport, gRPC state sync, discovery, and broker.
type Config struct {
	Enabled   bool            `json:"enabled"`
	Type      ClusterMode     `json:"type"`
	NodeID    string          `json:"node_id"`
	Region    string          `json:"region"`
	Peers     []string        `json:"peers"`
	Gossip    GossipConfig    `json:"gossip"`
	GRPC      GRPCConfig      `json:"grpc"`
	Discovery DiscoveryConfig `json:"discovery"`
	Broker    BrokerConfig    `json:"broker"`
	RateLimit RateLimitConfig `json:"rate_limit"`
}

// GossipConfig configures memberlist P2P gossip on port 10101.
type GossipConfig struct {
	Port          int                `json:"port"`           // Default 10101
	BindAddr      string             `json:"bind_addr"`      // Default "0.0.0.0"
	AdvertiseAddr string             `json:"advertise_addr"`
	AdvertisePort int                `json:"advertise_port"`
	SecretKey     string             `json:"secret_key"`     // Optional cluster encryption secret
	Config        GossipTimingConfig `json:"config"`
}

// GossipTimingConfig configures heartbeats and failure detection thresholds.
type GossipTimingConfig struct {
	TimeoutSeconds       int `json:"timeout_seconds"`        // Default 10
	SuccessThreshold     int `json:"success_threshold"`      // Default 3
	FailureThreshold     int `json:"failure_threshold"`      // Default 3
	TombstoneTTLSeconds  int `json:"tombstone_ttl_seconds"`  // Default 300 (5 minutes); 0 disables TTL pruning
	MaxDeadNodes         int `json:"max_dead_nodes"`         // Default 100; 0 disables capacity pruning
	PruneIntervalSeconds int `json:"prune_interval_seconds"` // Default 30 seconds
}

// GRPCConfig configures gRPC application state sync on port 10102.
type GRPCConfig struct {
	Port               int `json:"port"`                 // Default 10102
	BindAddr           string `json:"bind_addr"`         // Default "0.0.0.0"
	DialTimeoutSeconds int `json:"dial_timeout_seconds"` // Default 5
	DedupTTLSeconds    int `json:"dedup_ttl_seconds"`    // Default 300 (5 minutes)
}

// DiscoveryConfig configures node auto-discovery providers.
type DiscoveryConfig struct {
	Enabled             bool          `json:"enabled"`
	Type                string        `json:"type"` // "kubernetes", "dns", "udp", "consul", "etcd", "mdns", "static"
	ServiceName         string        `json:"service_name"`
	BindPort            int           `json:"bind_port"` // Default 10101
	DialTimeout         string        `json:"dial_timeout"`
	DialTimeoutDuration time.Duration `json:"-"`
	AllowedAddressSpace []string      `json:"allowed_address_space"`
	K8sNamespace        string        `json:"k8s_namespace"`
	K8sLabelSelector    string        `json:"k8s_label_selector"`
	DNSNames            []string      `json:"dns_names"`
	UDPBroadcastPort    int           `json:"udp_broadcast_port"` // e.g. 10103
	ConsulAddress       string        `json:"consul_address"`
	EtcdEndpoints       []string      `json:"etcd_endpoints"`
	MDNSService         string        `json:"mdns_service"`
}

// BrokerConfig configures centralized broker relay mode on port 50051.
type BrokerConfig struct {
	Address    string `json:"address"`     // Broker gRPC address, e.g. "broker.enterprise.internal:50051"
	TLS        bool   `json:"tls"`         // Connect via TLS
	AuthToken  string `json:"auth_token"`  // Shared authentication token
	ListenPort int    `json:"listen_port"` // Default 50051 (when running as broker daemon)
	BindAddr   string `json:"bind_addr"`   // Default "0.0.0.0"
}

// RateLimitConfig configures cluster-wide distributed rate-limit synchronization.
type RateLimitConfig struct {
	Backend      string        `json:"backend"`       // "auto", "redis", "p2p"
	KeyPrefix    string        `json:"key_prefix"`    // Default "airlok:rl:"
	SyncInterval time.Duration `json:"sync_interval"` // Default 20ms
}

// StateHandler processes incoming replicated entity updates.
type StateHandler func(ctx context.Context, entityType string, payload []byte) error

// MembershipListener notifies consumers of node membership events.
type MembershipListener interface {
	OnNodeJoin(node NodeInfo)
	OnNodeLeave(node NodeInfo)
	OnNodeUpdate(node NodeInfo)
}

// LeadershipListener notifies consumers of leader election events.
type LeadershipListener interface {
	OnLeaderElected(leader NodeInfo, isLocalNode bool)
	OnRegionalLeaderElected(region string, leader NodeInfo, isLocalNode bool)
}

// Replicated entity type constants (30+ entity types supported fleet-wide).
const (
	EntityVirtualKey             = "virtual_key"
	EntityGovernance             = "governance"
	EntityTeam                   = "team"
	EntityCustomer               = "customer"
	EntityBU                     = "business_unit_governance"
	EntityUserGov                = "user_governance"
	EntityAccessProfile          = "access_profile"
	EntityAPIKey                 = "api_key"
	EntityModelCatalog           = "model_catalog"
	EntityProvider               = "provider"
	EntityModelConfig            = "model_config"
	EntityPricing                = "pricing"
	EntityPricingOverride        = "pricing_override"
	EntityAuthConfig             = "auth_config"
	EntityRBAC                   = "rbac"
	EntityProxyConfig            = "proxy_config"
	EntityClientConfig           = "client_config"
	EntityRoutingRule            = "routing_rule"
	EntityLoadBalancing          = "load_balancing"
	EntityLoadBalancingLog       = "load_balancing_log"
	EntityMCPTool                = "mcp_tool"
	EntityVirtualMCP             = "virtual_mcp"
	EntityGuardrail              = "guardrail"
	EntityGuardrailConfig        = "guardrail_config"
	EntityGuardrailSampling      = "guardrail_sampling"
	EntityPlugin                 = "plugin"
	EntityObservabilityConnector = "observability_connector"
	EntityPromptDeployment       = "prompt_deployment"
	EntityKVStore                = "kv_store"
	EntityClusterDiagnostic      = "cluster_diagnostic"
	EntityRateLimitDelta         = "ratelimit_delta"
)
