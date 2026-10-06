package cluster

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/encoding"
)

// Action represents the mutation intent of a replicated state message.
type Action string

const (
	ActionUpsert    Action = "UPSERT"
	ActionDelete    Action = "DELETE"
	ActionReset     Action = "RESET"
	ActionHeartbeat Action = "HEARTBEAT"
	ActionSnapshot  Action = "SNAPSHOT"
)

// TrafficLane defines the multiplexed priority lane for broker relay frames.
type TrafficLane int

const (
	LaneGeneral        TrafficLane = 0
	LaneHeartbeat      TrafficLane = 1
	LaneGovernance     TrafficLane = 2
	LaneKVStore        TrafficLane = 3
	LaneCircuitBreaker TrafficLane = 4
	LaneLoadBalancer   TrafficLane = 5
	LaneDiagnostic     TrafficLane = 6
)

// String returns the human-readable lane name.
func (l TrafficLane) String() string {
	switch l {
	case LaneGeneral:
		return "general"
	case LaneHeartbeat:
		return "heartbeat"
	case LaneGovernance:
		return "governance"
	case LaneKVStore:
		return "kvstore"
	case LaneCircuitBreaker:
		return "circuit_breaker"
	case LaneLoadBalancer:
		return "load_balancer"
	case LaneDiagnostic:
		return "diagnostic"
	default:
		return "unknown"
	}
}

// FrameType identifies the frame purpose on the broker relay stream.
type FrameType int

const (
	FrameHandshake    FrameType = 0
	FrameHandshakeAck FrameType = 1
	FrameRoster       FrameType = 2
	FrameMessage      FrameType = 3
	FrameHeartbeat    FrameType = 4
	FrameDiagnostic   FrameType = 5
)

// SyncMessage is the fundamental replicated application state payload on port 10102.
type SyncMessage struct {
	MessageID    string   `json:"message_id"`       // UUID v4
	SenderNodeID string   `json:"sender_node_id"`   // Originating node ID
	SenderRegion string   `json:"sender_region"`   // Originating region
	EntityType   string   `json:"entity_type"`      // One of 30+ entity types
	EntityID     string   `json:"entity_id"`        // Target entity key or ID
	Action       Action   `json:"action"`           // UPSERT, DELETE, RESET, etc.
	Version      int64    `json:"version"`          // Monotonic sequence number
	TimestampNs  int64    `json:"timestamp_ns"`     // Unix nanosecond wall-clock for LWW conflict resolution
	TTLSeconds   int32    `json:"ttl_seconds"`      // Default 300 (5 minutes)
	Payload      []byte   `json:"payload"`          // Entity JSON or binary payload
	Capabilities []string `json:"capabilities,omitempty"` // Node capabilities e.g. ["ack:v1"]
}

// NewSyncMessage creates a new SyncMessage with a unique ID and current nanosecond timestamp.
func NewSyncMessage(senderNodeID, senderRegion, entityType, entityID string, action Action, payload []byte) *SyncMessage {
	return &SyncMessage{
		MessageID:    uuid.New().String(),
		SenderNodeID: senderNodeID,
		SenderRegion: senderRegion,
		EntityType:   entityType,
		EntityID:     entityID,
		Action:       action,
		TimestampNs:  time.Now().UnixNano(),
		TTLSeconds:   300,
		Payload:      payload,
		Capabilities: []string{"ack:v1"},
	}
}

// AckStatus represents the status of a replication acknowledgment.
type AckStatus int

const (
	AckStatusOK        AckStatus = 0
	AckStatusDuplicate AckStatus = 1
	AckStatusStale     AckStatus = 2
	AckStatusError     AckStatus = 3
)

// SyncAck is returned upon receipt of a SyncMessage.
type SyncAck struct {
	MessageID       string    `json:"message_id"`
	ResponderNodeID string    `json:"responder_node_id"`
	Status          AckStatus `json:"status"`
	ErrorMessage    string    `json:"error_message,omitempty"`
	TimestampNs     int64     `json:"timestamp_ns"`
}

// RelayFrame encapsulates multiplexed messages over the broker stream on port 50051.
type RelayFrame struct {
	FrameID      string      `json:"frame_id"`
	Type         FrameType   `json:"type"`
	Lane         TrafficLane `json:"lane"`
	SenderNodeID string      `json:"sender_node_id"`
	TargetNodeID string      `json:"target_node_id,omitempty"` // empty = broadcast to all peers
	AuthToken    string      `json:"auth_token,omitempty"`
	Payload      []byte      `json:"payload"`
	TimestampNs  int64       `json:"timestamp_ns"`
}

// RosterPayload encapsulates membership list pushed by broker to connected nodes.
type RosterPayload struct {
	RosterVersion int64      `json:"roster_version"`
	Members       []NodeInfo `json:"members"`
	LeaderNodeID  string     `json:"leader_node_id"`
}

// MarshalSyncMessage encodes SyncMessage to JSON.
func MarshalSyncMessage(msg *SyncMessage) ([]byte, error) {
	return json.Marshal(msg)
}

// UnmarshalSyncMessage decodes JSON into SyncMessage.
func UnmarshalSyncMessage(data []byte) (*SyncMessage, error) {
	var msg SyncMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// MarshalRelayFrame encodes RelayFrame to JSON.
func MarshalRelayFrame(frame *RelayFrame) ([]byte, error) {
	return json.Marshal(frame)
}

// UnmarshalRelayFrame decodes JSON into RelayFrame.
func UnmarshalRelayFrame(data []byte) (*RelayFrame, error) {
	var frame RelayFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		return nil, err
	}
	return &frame, nil
}

// rawCodec allows transparent passing of raw JSON or byte frames over gRPC.
type rawCodec struct{}

func (rawCodec) Marshal(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case []byte:
		return val, nil
	case *[]byte:
		return *val, nil
	default:
		return json.Marshal(v)
	}
}

func (rawCodec) Unmarshal(data []byte, v interface{}) error {
	switch val := v.(type) {
	case *[]byte:
		*val = append([]byte(nil), data...)
		return nil
	default:
		return json.Unmarshal(data, v)
	}
}

func (rawCodec) Name() string {
	return "raw"
}

func init() {
	encoding.RegisterCodec(rawCodec{})
}

