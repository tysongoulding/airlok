package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// RateLimitChargeRequest encapsulates a forward charge RPC to the primary hash ring node.
type RateLimitChargeRequest struct {
	Key      string `json:"key"`
	Amount   int64  `json:"amount"`
	Capacity int64  `json:"capacity"`
	WindowMs int64  `json:"window_ms"`
	NodeID   string `json:"node_id"`
}

// RateLimitChargeResponse contains the evaluation result from the primary node.
type RateLimitChargeResponse struct {
	Allowed   bool   `json:"allowed"`
	Remaining int64  `json:"remaining"`
	ResetMs   int64  `json:"reset_ms"`
	Error     string `json:"error,omitempty"`
}

// ChargeHandler evaluates forwarded rate limit charges on the primary node.
type ChargeHandler func(ctx context.Context, req *RateLimitChargeRequest) *RateLimitChargeResponse

// GRPCSyncManager coordinates state synchronization across nodes over port 10102.
type GRPCSyncManager struct {
	mu              sync.RWMutex
	nodeID          string
	region          string
	port            int
	bindAddr        string
	dedup           *DedupCache
	handlers        map[string]StateHandler // entity_type -> StateHandler
	chargeHandlerMu sync.RWMutex
	chargeHandler   ChargeHandler
	clients         map[string]*grpc.ClientConn // targetNodeID or addr -> conn
	server          *grpc.Server
	listener        net.Listener
	historyMu       sync.RWMutex
	history         []*SyncMessage // Recent message ring buffer for catch-up
	maxHistory      int
	stopCh          chan struct{}
	closeOnce       sync.Once
}

// NewGRPCSyncManager initializes the gRPC state synchronization manager.
func NewGRPCSyncManager(nodeID, region string, port int, bindAddr string, dedupTTL time.Duration) *GRPCSyncManager {
	if port == 0 {
		port = 10102
	} else if port < 0 {
		port = 0
	}
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	if dedupTTL <= 0 {
		dedupTTL = 5 * time.Minute
	}
	return &GRPCSyncManager{
		nodeID:     nodeID,
		region:     region,
		port:       port,
		bindAddr:   bindAddr,
		dedup:      NewDedupCache(dedupTTL),
		handlers:   make(map[string]StateHandler),
		clients:    make(map[string]*grpc.ClientConn),
		history:    make([]*SyncMessage, 0, 1000),
		maxHistory: 1000,
		stopCh:     make(chan struct{}),
	}
}

// RegisterHandler registers a callback handler for a specific replicated entity type.
func (s *GRPCSyncManager) RegisterHandler(entityType string, handler StateHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[entityType] = handler
}

// RegisterChargeHandler registers a callback handler for forwarded rate limit charges.
func (s *GRPCSyncManager) RegisterChargeHandler(handler ChargeHandler) {
	s.chargeHandlerMu.Lock()
	defer s.chargeHandlerMu.Unlock()
	s.chargeHandler = handler
}

// Start binds the TCP listener and launches the gRPC sync server on port 10102.
func (s *GRPCSyncManager) Start() error {
	addr := fmt.Sprintf("%s:%d", s.bindAddr, s.port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind gRPC sync port %d: %w", s.port, err)
	}
	s.listener = lis

	// Update port in case port 0 was passed for ephemeral testing
	if tcpAddr, ok := lis.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}

	s.server = grpc.NewServer(
		grpc.ForceServerCodec(rawCodec{}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    15 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.UnknownServiceHandler(s.handleUnknownRPC),
	)

	go func() {
		_ = s.server.Serve(lis)
	}()

	return nil
}

// Stop shuts down the gRPC server and client pool.
func (s *GRPCSyncManager) Stop() {
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})

	if s.server != nil {
		s.server.GracefulStop()
	}
	if s.dedup != nil {
		s.dedup.Close()
	}

	s.mu.Lock()
	for _, conn := range s.clients {
		_ = conn.Close()
	}
	s.clients = make(map[string]*grpc.ClientConn)
	s.mu.Unlock()
}

// Port returns the bound gRPC port.
func (s *GRPCSyncManager) Port() int {
	return s.port
}

// BroadcastState creates and broadcasts a SyncMessage to a list of target peer addresses over port 10102.
func (s *GRPCSyncManager) BroadcastState(ctx context.Context, entityType string, payload []byte, peerAddrs []string) error {
	msg := NewSyncMessage(s.nodeID, s.region, entityType, "", ActionUpsert, payload)
	return s.BroadcastSyncMessage(ctx, msg, peerAddrs)
}

// BroadcastSyncMessage dispatches a prepared SyncMessage to all provided peer addresses.
func (s *GRPCSyncManager) BroadcastSyncMessage(ctx context.Context, msg *SyncMessage, peerAddrs []string) error {
	// Record in local history ring buffer for catch-up
	s.recordHistory(msg)

	// Record in local dedup cache so local node doesn't re-process its own broadcasts
	s.dedup.CheckAndRecord(msg.MessageID)

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error

	for _, addr := range peerAddrs {
		if addr == "" {
			continue
		}
		wg.Add(1)
		go func(peerAddr string) {
			defer wg.Done()
			if err := s.sendToPeer(ctx, peerAddr, msg); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
			}
		}(addr)
	}

	wg.Wait()
	return firstErr
}

// sendToPeer dispatches SyncMessage to a single peer via pooled gRPC client connection.
func (s *GRPCSyncManager) sendToPeer(ctx context.Context, peerAddr string, msg *SyncMessage) error {
	conn, err := s.getOrCreateClientConn(peerAddr)
	if err != nil {
		return err
	}

	data, err := MarshalSyncMessage(msg)
	if err != nil {
		return err
	}

	// Invoke raw gRPC method /bifrost.cluster.v1.SyncService/Broadcast
	var reply []byte
	return conn.Invoke(ctx, "/bifrost.cluster.v1.SyncService/Broadcast", data, &reply)
}

// SendChargeRPC invokes unary /bifrost.cluster.v1.SyncService/RateLimitCharge on peer.
func (s *GRPCSyncManager) SendChargeRPC(ctx context.Context, peerAddr string, req *RateLimitChargeRequest) (*RateLimitChargeResponse, error) {
	conn, err := s.getOrCreateClientConn(peerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer %s: %w", peerAddr, err)
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal charge request: %w", err)
	}

	var reply []byte
	if err := conn.Invoke(ctx, "/bifrost.cluster.v1.SyncService/RateLimitCharge", data, &reply); err != nil {
		return nil, fmt.Errorf("charge RPC to %s failed: %w", peerAddr, err)
	}

	var resp RateLimitChargeResponse
	if err := json.Unmarshal(reply, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal charge response from %s: %w", peerAddr, err)
	}

	return &resp, nil
}

func (s *GRPCSyncManager) getOrCreateClientConn(peerAddr string) (*grpc.ClientConn, error) {
	s.mu.RLock()
	conn, ok := s.clients[peerAddr]
	s.mu.RUnlock()
	if ok {
		return conn, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if conn, ok := s.clients[peerAddr]; ok {
		return conn, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, peerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                15 * time.Second,
			Timeout:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial peer gRPC %s: %w", peerAddr, err)
	}

	s.clients[peerAddr] = conn
	return conn, nil
}

// FetchCatchUp opens a server-streaming CatchUp RPC to peerAddr and processes missed historical messages.
func (s *GRPCSyncManager) FetchCatchUp(ctx context.Context, peerAddr string) error {
	conn, err := s.getOrCreateClientConn(peerAddr)
	if err != nil {
		return fmt.Errorf("failed to get client conn for catchup from %s: %w", peerAddr, err)
	}

	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "CatchUp",
		ServerStreams: true,
	}, "/bifrost.cluster.v1.SyncService/CatchUp")
	if err != nil {
		return fmt.Errorf("failed to open CatchUp stream to %s: %w", peerAddr, err)
	}

	for {
		var data []byte
		err := stream.RecvMsg(&data)
		if err != nil {
			// Normal EOF when server finishes sending history buffer
			if errors.Is(err, io.EOF) || status.Code(err) == codes.OK {
				break
			}
			return fmt.Errorf("error reading CatchUp stream from %s: %w", peerAddr, err)
		}

		msg, err := UnmarshalSyncMessage(data)
		if err != nil {
			continue
		}

		_ = s.ProcessIncomingMessage(ctx, msg)
	}

	return nil
}

// ProcessIncomingMessage processes a SyncMessage with deduplication, LWW verification, and handler dispatch.
func (s *GRPCSyncManager) ProcessIncomingMessage(ctx context.Context, msg *SyncMessage) *SyncAck {
	// 1. 5-minute TTL Deduplication Check
	if s.dedup.CheckAndRecord(msg.MessageID) {
		return &SyncAck{
			MessageID:       msg.MessageID,
			ResponderNodeID: s.nodeID,
			Status:          AckStatusDuplicate,
			TimestampNs:     time.Now().UnixNano(),
		}
	}

	// 2. Last-Write-Wins (LWW) Nanosecond Conflict Resolution Check
	entityKey := fmt.Sprintf("%s:%s", msg.EntityType, msg.EntityID)
	if !s.dedup.CheckLWW(entityKey, msg.TimestampNs) {
		return &SyncAck{
			MessageID:       msg.MessageID,
			ResponderNodeID: s.nodeID,
			Status:          AckStatusStale,
			ErrorMessage:    "stale update rejected under LWW nanosecond rule",
			TimestampNs:     time.Now().UnixNano(),
		}
	}

	// Record in local history ring buffer so this node can serve CatchUp if it later becomes leader
	s.recordHistory(msg)

	// 3. Dispatch to registered entity StateHandler
	s.mu.RLock()
	handler, ok := s.handlers[msg.EntityType]
	s.mu.RUnlock()

	if !ok {
		// Unknown entity type is accepted as a forward-compatible ACK
		return &SyncAck{
			MessageID:       msg.MessageID,
			ResponderNodeID: s.nodeID,
			Status:          AckStatusOK,
			TimestampNs:     time.Now().UnixNano(),
		}
	}

	if err := handler(ctx, msg.EntityType, msg.Payload); err != nil {
		return &SyncAck{
			MessageID:       msg.MessageID,
			ResponderNodeID: s.nodeID,
			Status:          AckStatusError,
			ErrorMessage:    err.Error(),
			TimestampNs:     time.Now().UnixNano(),
		}
	}

	return &SyncAck{
		MessageID:       msg.MessageID,
		ResponderNodeID: s.nodeID,
		Status:          AckStatusOK,
		TimestampNs:     time.Now().UnixNano(),
	}
}

// handleUnknownRPC handles raw gRPC stream and unary invocations for SyncService.
func (s *GRPCSyncManager) handleUnknownRPC(srv interface{}, stream grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		return status.Errorf(codes.Internal, "cannot extract method from stream")
	}

	if stringsHasSuffix(method, "Broadcast") {
		// Unary Broadcast RPC
		var reqData []byte
		if err := stream.RecvMsg(&reqData); err != nil {
			return err
		}

		msg, err := UnmarshalSyncMessage(reqData)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to decode SyncMessage: %v", err)
		}

		ack := s.ProcessIncomingMessage(stream.Context(), msg)
		ackBytes, _ := json.Marshal(ack)
		return stream.SendMsg(ackBytes)
	}

	if stringsHasSuffix(method, "CatchUp") {
		// Catch-up replay RPC
		s.historyMu.RLock()
		msgs := append([]*SyncMessage(nil), s.history...)
		s.historyMu.RUnlock()

		for _, msg := range msgs {
			bytes, _ := MarshalSyncMessage(msg)
			if err := stream.SendMsg(bytes); err != nil {
				return err
			}
		}
		return nil
	}

	if stringsHasSuffix(method, "RateLimitCharge") {
		var reqData []byte
		if err := stream.RecvMsg(&reqData); err != nil {
			return err
		}

		var req RateLimitChargeRequest
		if err := json.Unmarshal(reqData, &req); err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to decode RateLimitChargeRequest: %v", err)
		}

		s.chargeHandlerMu.RLock()
		handler := s.chargeHandler
		s.chargeHandlerMu.RUnlock()

		if handler == nil {
			return status.Errorf(codes.Unavailable, "rate limit charge handler not registered")
		}

		resp := handler(stream.Context(), &req)
		respBytes, _ := json.Marshal(resp)
		return stream.SendMsg(respBytes)
	}

	return status.Errorf(codes.Unimplemented, "unimplemented gRPC method %s", method)
}

func (s *GRPCSyncManager) recordHistory(msg *SyncMessage) {
	s.historyMu.Lock()
	defer s.historyMu.Unlock()

	if len(s.history) >= s.maxHistory {
		s.history = s.history[1:]
	}
	s.history = append(s.history, msg)
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
