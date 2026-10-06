package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// BrokerClientSession tracks a single connected node's multiplexed stream on the broker server.
type BrokerClientSession struct {
	nodeID    string
	metadata  NodeInfo
	lanes     map[TrafficLane]chan *RelayFrame
	stream    grpc.ServerStream
	done      chan struct{}
	closeOnce sync.Once
}

// BrokerServer runs the centralized gRPC relay broker on port 50051 for outbound-only nodes.
type BrokerServer struct {
	listenPort    int
	bindAddr      string
	authToken     string
	clientsMu     sync.RWMutex
	clients       map[string]*BrokerClientSession // node_id -> session
	rosterVersion int64
	server        *grpc.Server
	listener      net.Listener
	stopCh        chan struct{}
	closeOnce     sync.Once
}

// NewBrokerServer creates a new centralized broker relay server.
func NewBrokerServer(listenPort int, bindAddr, authToken string) *BrokerServer {
	if listenPort == 0 {
		listenPort = 50051
	}
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	return &BrokerServer{
		listenPort: listenPort,
		bindAddr:   bindAddr,
		authToken:  authToken,
		clients:    make(map[string]*BrokerClientSession),
		stopCh:     make(chan struct{}),
	}
}

// Start begins serving gRPC connections on port 50051.
func (b *BrokerServer) Start() error {
	addr := fmt.Sprintf("%s:%d", b.bindAddr, b.listenPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind broker relay port %d: %w", b.listenPort, err)
	}
	b.listener = lis

	if tcpAddr, ok := lis.Addr().(*net.TCPAddr); ok {
		b.listenPort = tcpAddr.Port
	}

	b.server = grpc.NewServer(
		grpc.ForceServerCodec(rawCodec{}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    15 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.UnknownServiceHandler(b.handleRelayStream),
	)

	go func() {
		_ = b.server.Serve(lis)
	}()

	go b.periodicRosterLoop()
	return nil
}

// Stop shuts down the broker server and client streams.
func (b *BrokerServer) Stop() {
	b.closeOnce.Do(func() {
		close(b.stopCh)
	})

	b.clientsMu.Lock()
	for _, session := range b.clients {
		session.closeOnce.Do(func() {
			close(session.done)
		})
	}
	b.clients = make(map[string]*BrokerClientSession)
	b.clientsMu.Unlock()

	if b.server != nil {
		b.server.GracefulStop()
	}
}

// Port returns the bound broker port.
func (b *BrokerServer) Port() int {
	return b.listenPort
}

// FanOut relays a frame from sender to all other connected client sessions (never back to sender).
func (b *BrokerServer) FanOut(senderNodeID string, frame *RelayFrame) {
	b.clientsMu.RLock()
	defer b.clientsMu.RUnlock()

	for nodeID, session := range b.clients {
		if nodeID == senderNodeID {
			continue // Never echo back to originating node
		}
		if frame.TargetNodeID != "" && frame.TargetNodeID != nodeID {
			continue // Targeted frame intended for another specific node
		}

		laneCh, ok := session.lanes[frame.Lane]
		if !ok {
			laneCh = session.lanes[LaneGeneral]
		}

		select {
		case laneCh <- frame:
		default:
			// Non-blocking buffer: drop or log frame under backpressure
		}
	}
}

// BroadcastRoster compiles the current roster of connected nodes and pushes FRAME_ROSTER to all sessions.
func (b *BrokerServer) BroadcastRoster() {
	b.clientsMu.Lock()
	b.rosterVersion++
	members := make([]NodeInfo, 0, len(b.clients))
	var aliveIDs []string

	for id, s := range b.clients {
		members = append(members, s.metadata)
		aliveIDs = append(aliveIDs, id)
	}

	sort.Strings(aliveIDs)
	leaderID := ""
	if len(aliveIDs) > 0 {
		leaderID = aliveIDs[0] // Deterministic lexicographical election
	}

	for _, s := range b.clients {
		s.metadata.IsLeader = (s.nodeID == leaderID)
	}

	roster := RosterPayload{
		RosterVersion: b.rosterVersion,
		Members:       members,
		LeaderNodeID:  leaderID,
	}
	b.clientsMu.Unlock()

	rosterJSON, _ := json.Marshal(roster)
	frame := &RelayFrame{
		FrameID:      fmt.Sprintf("roster-%d", roster.RosterVersion),
		Type:         FrameRoster,
		Lane:         LaneHeartbeat,
		SenderNodeID: "broker",
		Payload:      rosterJSON,
		TimestampNs:  time.Now().UnixNano(),
	}

	b.FanOut("", frame)
}

func (b *BrokerServer) periodicRosterLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.BroadcastRoster()
		}
	}
}

func (b *BrokerServer) handleRelayStream(srv interface{}, stream grpc.ServerStream) error {
	// First frame must be Handshake
	var handshakeBytes []byte
	if err := stream.RecvMsg(&handshakeBytes); err != nil {
		return err
	}

	frame, err := UnmarshalRelayFrame(handshakeBytes)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to decode handshake frame: %v", err)
	}

	// Verify auth token if configured
	if b.authToken != "" && frame.AuthToken != b.authToken {
		return status.Errorf(codes.Unauthenticated, "invalid broker auth token")
	}

	nodeID := frame.SenderNodeID
	if nodeID == "" {
		nodeID = fmt.Sprintf("node-%d", time.Now().UnixNano())
	}

	var metadata NodeInfo
	if len(frame.Payload) > 0 {
		_ = json.Unmarshal(frame.Payload, &metadata)
	}
	metadata.NodeID = nodeID
	metadata.State = NodeStateAlive
	metadata.LastSeen = time.Now()

	// Initialize 7 dedicated traffic lane channels
	session := &BrokerClientSession{
		nodeID:   nodeID,
		metadata: metadata,
		lanes:    make(map[TrafficLane]chan *RelayFrame),
		stream:   stream,
		done:     make(chan struct{}),
	}
	for lane := LaneGeneral; lane <= LaneDiagnostic; lane++ {
		session.lanes[lane] = make(chan *RelayFrame, 128)
	}

	b.clientsMu.Lock()
	b.clients[nodeID] = session
	b.clientsMu.Unlock()

	// Send Handshake ACK
	ackFrame := &RelayFrame{
		FrameID:      frame.FrameID,
		Type:         FrameHandshakeAck,
		Lane:         LaneGeneral,
		SenderNodeID: "broker",
		TimestampNs:  time.Now().UnixNano(),
	}
	ackBytes, _ := MarshalRelayFrame(ackFrame)
	if err := stream.SendMsg(ackBytes); err != nil {
		b.removeSession(nodeID)
		return err
	}

	// Broadcast updated roster to all nodes
	b.BroadcastRoster()

	// Launch multiplexed lane writer goroutine
	go b.writerLoop(session)

	// Reader loop
	defer func() {
		b.removeSession(nodeID)
		b.BroadcastRoster()
	}()

	for {
		var incomingBytes []byte
		if err := stream.RecvMsg(&incomingBytes); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		inFrame, err := UnmarshalRelayFrame(incomingBytes)
		if err != nil {
			continue
		}

		if inFrame.Type == FrameHeartbeat {
			b.clientsMu.Lock()
			if s, ok := b.clients[nodeID]; ok {
				s.metadata.LastSeen = time.Now()
			}
			b.clientsMu.Unlock()
			continue
		}

		// Relay frame to peer nodes
		b.FanOut(nodeID, inFrame)
	}
}

func (b *BrokerServer) writerLoop(session *BrokerClientSession) {
	for {
		select {
		case <-session.done:
			return
		case <-b.stopCh:
			return
		case frame := <-session.lanes[LaneHeartbeat]:
			b.sendFrame(session, frame)
		case frame := <-session.lanes[LaneCircuitBreaker]:
			b.sendFrame(session, frame)
		case frame := <-session.lanes[LaneGovernance]:
			b.sendFrame(session, frame)
		case frame := <-session.lanes[LaneKVStore]:
			b.sendFrame(session, frame)
		case frame := <-session.lanes[LaneGeneral]:
			b.sendFrame(session, frame)
		case frame := <-session.lanes[LaneLoadBalancer]:
			b.sendFrame(session, frame)
		case frame := <-session.lanes[LaneDiagnostic]:
			b.sendFrame(session, frame)
		}
	}
}

func (b *BrokerServer) sendFrame(session *BrokerClientSession, frame *RelayFrame) {
	data, err := MarshalRelayFrame(frame)
	if err == nil {
		_ = session.stream.SendMsg(data)
	}
}

func (b *BrokerServer) removeSession(nodeID string) {
	b.clientsMu.Lock()
	if s, ok := b.clients[nodeID]; ok {
		s.closeOnce.Do(func() {
			close(s.done)
		})
		delete(b.clients, nodeID)
	}
	b.clientsMu.Unlock()
}

// BrokerClient connects outbound-only nodes to the centralized broker relay over port 50051.
type BrokerClient struct {
	mu             sync.RWMutex
	brokerURL      string
	nodeID         string
	region         string
	authToken      string
	useTLS         bool
	conn           *grpc.ClientConn
	stream         grpc.ClientStream
	lanes          map[TrafficLane]chan *RelayFrame
	onMessage      func(msg *SyncMessage)
	onRosterUpdate func(roster *RosterPayload)
	roster         []NodeInfo
	currentLeader  string
	stopCh         chan struct{}
	closeOnce      sync.Once
}

// NewBrokerClient creates an outbound broker relay client.
func NewBrokerClient(brokerURL, nodeID, region, authToken string, useTLS bool, onMessage func(msg *SyncMessage), onRosterUpdate func(roster *RosterPayload)) *BrokerClient {
	c := &BrokerClient{
		brokerURL:      brokerURL,
		nodeID:         nodeID,
		region:         region,
		authToken:      authToken,
		useTLS:         useTLS,
		lanes:          make(map[TrafficLane]chan *RelayFrame),
		onMessage:      onMessage,
		onRosterUpdate: onRosterUpdate,
		stopCh:         make(chan struct{}),
	}
	for lane := LaneGeneral; lane <= LaneDiagnostic; lane++ {
		c.lanes[lane] = make(chan *RelayFrame, 128)
	}
	return c
}

// Connect establishes persistent outbound stream with Cloud Run 60-min cap handling and keepalives.
func (c *BrokerClient) Connect(ctx context.Context) error {
	addr := c.brokerURL
	if stringsHasPrefix(addr, "grpc://") {
		addr = addr[7:]
	}

	var dialOpts []grpc.DialOption
	if c.useTLS {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})))
	dialOpts = append(dialOpts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                15 * time.Second,
		Timeout:             5 * time.Second,
		PermitWithoutStream: true,
	}))

	conn, err := grpc.DialContext(ctx, addr, dialOpts...)
	if err != nil {
		return fmt.Errorf("failed to dial broker %s: %w", addr, err)
	}
	c.conn = conn

	// Launch background connection and reader loop
	go c.runLoop(ctx)
	return nil
}

func (c *BrokerClient) runLoop(ctx context.Context) {
	backoff := 1 * time.Second
	for {
		select {
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		err := c.streamSession(ctx)
		if err != nil {
			select {
			case <-c.stopCh:
				return
			case <-time.After(backoff):
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		} else {
			backoff = 1 * time.Second
		}
	}
}

func (c *BrokerClient) streamSession(ctx context.Context) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()

	// Raw bidirectional stream call: /bifrost.cluster.v1.BrokerRelayService/RelayStream
	streamDesc := &grpc.StreamDesc{
		StreamName:    "RelayStream",
		ServerStreams: true,
		ClientStreams: true,
	}

	stream, err := c.conn.NewStream(sessionCtx, streamDesc, "/bifrost.cluster.v1.BrokerRelayService/RelayStream")
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.stream = stream
	c.mu.Unlock()

	// Handshake frame
	localInfo := NodeInfo{
		NodeID:   c.nodeID,
		Region:   c.region,
		State:    NodeStateAlive,
		LastSeen: time.Now(),
	}
	infoBytes, _ := json.Marshal(localInfo)
	handshake := &RelayFrame{
		FrameID:      fmt.Sprintf("hs-%s", c.nodeID),
		Type:         FrameHandshake,
		Lane:         LaneGeneral,
		SenderNodeID: c.nodeID,
		AuthToken:    c.authToken,
		Payload:      infoBytes,
		TimestampNs:  time.Now().UnixNano(),
	}
	hsBytes, _ := MarshalRelayFrame(handshake)
	if err := stream.SendMsg(hsBytes); err != nil {
		return err
	}

	// Writer worker with synchronous termination barrier
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.clientWriterLoop(sessionCtx, stream, sessionCancel)
	}()

	defer func() {
		sessionCancel()
		<-writerDone
		c.mu.Lock()
		c.stream = nil
		c.mu.Unlock()
	}()

	// Reader loop
	for {
		var respBytes []byte
		if err := stream.RecvMsg(&respBytes); err != nil {
			return err
		}

		frame, err := UnmarshalRelayFrame(respBytes)
		if err != nil {
			continue
		}

		switch frame.Type {
		case FrameRoster:
			var roster RosterPayload
			if err := json.Unmarshal(frame.Payload, &roster); err == nil {
				c.mu.Lock()
				c.roster = roster.Members
				c.currentLeader = roster.LeaderNodeID
				c.mu.Unlock()
				if c.onRosterUpdate != nil {
					c.onRosterUpdate(&roster)
				}
			}
		case FrameMessage:
			msg, err := UnmarshalSyncMessage(frame.Payload)
			if err == nil && c.onMessage != nil {
				c.onMessage(msg)
			}
		}
	}
}

func (c *BrokerClient) clientWriterLoop(ctx context.Context, stream grpc.ClientStream, cancelSession context.CancelFunc) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	handleSend := func(frame *RelayFrame) bool {
		if err := c.sendFrame(stream, frame); err != nil {
			c.requeueFrame(frame)
			cancelSession()
			return false
		}
		return true
	}

	for {
		select {
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Heartbeat frame
			hb := &RelayFrame{
				FrameID:      fmt.Sprintf("hb-%s-%d", c.nodeID, time.Now().UnixNano()),
				Type:         FrameHeartbeat,
				Lane:         LaneHeartbeat,
				SenderNodeID: c.nodeID,
				TimestampNs:  time.Now().UnixNano(),
			}
			bytes, err := MarshalRelayFrame(hb)
			if err == nil {
				if err := stream.SendMsg(bytes); err != nil {
					cancelSession()
					return
				}
			}
		case frame := <-c.lanes[LaneHeartbeat]:
			if !handleSend(frame) {
				return
			}
		case frame := <-c.lanes[LaneCircuitBreaker]:
			if !handleSend(frame) {
				return
			}
		case frame := <-c.lanes[LaneGovernance]:
			if !handleSend(frame) {
				return
			}
		case frame := <-c.lanes[LaneKVStore]:
			if !handleSend(frame) {
				return
			}
		case frame := <-c.lanes[LaneGeneral]:
			if !handleSend(frame) {
				return
			}
		case frame := <-c.lanes[LaneLoadBalancer]:
			if !handleSend(frame) {
				return
			}
		case frame := <-c.lanes[LaneDiagnostic]:
			if !handleSend(frame) {
				return
			}
		}
	}
}

func (c *BrokerClient) sendFrame(stream grpc.ClientStream, frame *RelayFrame) error {
	bytes, err := MarshalRelayFrame(frame)
	if err != nil {
		return err
	}
	return stream.SendMsg(bytes)
}

func (c *BrokerClient) requeueFrame(frame *RelayFrame) {
	if frame == nil {
		return
	}
	c.mu.RLock()
	laneCh, ok := c.lanes[frame.Lane]
	if !ok {
		laneCh = c.lanes[LaneGeneral]
	}
	c.mu.RUnlock()

	select {
	case laneCh <- frame:
	default:
		// Queue full under disconnect, dropped under backpressure
	}
}

// SendMessage queues a SyncMessage onto the appropriate outbound traffic lane.
func (c *BrokerClient) SendMessage(lane TrafficLane, msg *SyncMessage) error {
	payload, err := MarshalSyncMessage(msg)
	if err != nil {
		return err
	}

	frame := &RelayFrame{
		FrameID:      msg.MessageID,
		Type:         FrameMessage,
		Lane:         lane,
		SenderNodeID: c.nodeID,
		Payload:      payload,
		TimestampNs:  msg.TimestampNs,
	}

	c.mu.RLock()
	laneCh, ok := c.lanes[lane]
	if !ok {
		laneCh = c.lanes[LaneGeneral]
	}
	c.mu.RUnlock()

	select {
	case laneCh <- frame:
		return nil
	default:
		return fmt.Errorf("lane buffer %s full", lane.String())
	}
}

// GetLeaderID returns the leader ID computed from the broker roster.
func (c *BrokerClient) GetLeaderID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentLeader
}

// GetRoster returns the current membership list.
func (c *BrokerClient) GetRoster() []NodeInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]NodeInfo(nil), c.roster...)
}

// Close disconnects the client.
func (c *BrokerClient) Close() {
	c.closeOnce.Do(func() {
		close(c.stopCh)
	})
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
