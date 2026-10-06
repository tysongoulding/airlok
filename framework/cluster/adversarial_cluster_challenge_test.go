package cluster

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// ADVERSARIAL CHALLENGE 3: BROKER RELAY MULTIPLEXING STRESS (ALL 7 LANES)
// ============================================================================

func TestAdversarial_BrokerMultiplexing_7TrafficLanes_NoStarvationOrDeadlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Boot Broker Server on ephemeral port
	broker := NewBrokerServer(0, "127.0.0.1", "adversarial-secret")
	if err := broker.Start(); err != nil {
		t.Fatalf("failed to start broker server: %v", err)
	}
	defer broker.Stop()

	brokerAddr := fmt.Sprintf("127.0.0.1:%d", broker.Port())

	// 2. Connect Receiver Client (Client 2)
	lanes := []TrafficLane{
		LaneGeneral,
		LaneHeartbeat,
		LaneGovernance,
		LaneKVStore,
		LaneCircuitBreaker,
		LaneLoadBalancer,
		LaneDiagnostic,
	}

	laneCounters := make(map[TrafficLane]*int64)
	for _, l := range lanes {
		var cnt int64
		laneCounters[l] = &cnt
	}

	client2 := NewBrokerClient(brokerAddr, "receiver-node", "us-east-1", "adversarial-secret", false, func(msg *SyncMessage) {
		for _, l := range lanes {
			if msg.EntityType == fmt.Sprintf("stress-%s", l.String()) {
				atomic.AddInt64(laneCounters[l], 1)
				break
			}
		}
	}, nil)
	if err := client2.Connect(ctx); err != nil {
		t.Fatalf("receiver client failed to connect: %v", err)
	}
	defer client2.Close()

	// 3. Connect Sender Client (Client 1)
	client1 := NewBrokerClient(brokerAddr, "sender-node", "us-east-1", "adversarial-secret", false, nil, nil)
	if err := client1.Connect(ctx); err != nil {
		t.Fatalf("sender client failed to connect: %v", err)
	}
	defer client1.Close()

	// Allow connection handshake and roster dissemination to settle
	time.Sleep(250 * time.Millisecond)

	// 4. Saturate broker relay with concurrent bursts across ALL 7 traffic lanes
	const messagesPerLane = 30
	var wg sync.WaitGroup
	var sendFailures int64

	t0 := time.Now()
	for _, lane := range lanes {
		wg.Add(1)
		go func(l TrafficLane) {
			defer wg.Done()
			for i := 0; i < messagesPerLane; i++ {
				msg := NewSyncMessage(
					"sender-node",
					"us-east-1",
					fmt.Sprintf("stress-%s", l.String()),
					fmt.Sprintf("msg-%s-%d", l.String(), i),
					ActionUpsert,
					[]byte(fmt.Sprintf(`{"lane": "%s", "seq": %d}`, l.String(), i)),
				)
				if err := client1.SendMessage(l, msg); err != nil {
					atomic.AddInt64(&sendFailures, 1)
				}
				// Slight micro-yield to simulate high-frequency asynchronous traffic
				time.Sleep(50 * time.Microsecond)
			}
		}(lane)
	}

	wg.Wait()
	t.Logf("Finished dispatching %d messages across 7 lanes in %v (sendFailures=%d)",
		len(lanes)*messagesPerLane, time.Since(t0), sendFailures)

	// 5. Wait for all messages to be multiplexed and relayed to receiver
	deadline := time.Now().Add(4 * time.Second)
	allReceived := false
	for time.Now().Before(deadline) {
		totalReceived := int64(0)
		everyLaneReceivedSomething := true
		for _, l := range lanes {
			cnt := atomic.LoadInt64(laneCounters[l])
			totalReceived += cnt
			if cnt == 0 {
				everyLaneReceivedSomething = false
			}
		}
		if everyLaneReceivedSomething && totalReceived >= int64(len(lanes)*messagesPerLane) {
			allReceived = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 6. Empirical assertions: no lane must starve, no deadlock
	for _, l := range lanes {
		received := atomic.LoadInt64(laneCounters[l])
		t.Logf("Lane %-16s -> Received: %d / %d", l.String(), received, messagesPerLane)
		if received == 0 {
			t.Fatalf("STARVATION VIOLATION: Lane %s starved and received 0 messages under saturation!", l.String())
		}
		if received < int64(messagesPerLane) {
			t.Errorf("Warning: Lane %s experienced packet drop under backpressure: got %d, expected %d",
				l.String(), received, messagesPerLane)
		}
	}

	if !allReceived {
		t.Fatalf("DEADLOCK OR DROPS: Broker relay failed to deliver all multiplexed frames within timeout")
	}
}

// ============================================================================
// ADVERSARIAL CHALLENGE: TOKEN BUCKET HIGH CONCURRENCY BURST (1000 GOROUTINES)
// ============================================================================

func TestAdversarial_InMemTokenBucket_1000GoroutineBurst_ZeroDrift(t *testing.T) {
	bucket := NewInMemTokenBucket("stress-burst-key", 100, 10*time.Second)
	now := time.Now()

	const numGoroutines = 1000
	const capacity = 100

	var startGate sync.WaitGroup
	startGate.Add(1)

	var doneWg sync.WaitGroup
	var successes int64
	var rejections int64

	for i := 0; i < numGoroutines; i++ {
		doneWg.Add(1)
		go func() {
			defer doneWg.Done()
			startGate.Wait()

			allowed, _, _, _ := bucket.CheckAndCharge(now, 1, capacity, 10*time.Second)
			if allowed {
				atomic.AddInt64(&successes, 1)
			} else {
				atomic.AddInt64(&rejections, 1)
			}
		}()
	}

	startGate.Done()
	doneWg.Wait()

	t.Logf("1000-Goroutine InMemTokenBucket Burst: Successes=%d, Rejections=%d (Capacity=%d)",
		successes, rejections, capacity)

	if successes != capacity {
		t.Fatalf("VIOLATION: Expected exactly %d successes, got %d (drift=%d)",
			capacity, successes, successes-capacity)
	}
	if rejections != numGoroutines-capacity {
		t.Fatalf("VIOLATION: Expected exactly %d rejections, got %d",
			numGoroutines-capacity, rejections)
	}

	// Verify remaining is exactly 0
	bucket.mu.Lock()
	rem := bucket.Remaining
	bucket.mu.Unlock()
	if rem != 0 {
		t.Fatalf("VIOLATION: Bucket remaining is %d, expected strictly 0", rem)
	}
}

// ============================================================================
// ADVERSARIAL CHALLENGE: STATE REPLICATION gRPC SYNC DELAY (<50MS)
// ============================================================================

func TestAdversarial_GRPCSyncDelay_Under50ms(t *testing.T) {
	ctx := context.Background()

	node1 := NewGRPCSyncManager("node-sync-1", "us-east-1", -1, "127.0.0.1", 5*time.Minute)
	if err := node1.Start(); err != nil {
		t.Fatalf("failed to start node1: %v", err)
	}
	defer node1.Stop()

	node2 := NewGRPCSyncManager("node-sync-2", "us-east-1", -1, "127.0.0.1", 5*time.Minute)
	if err := node2.Start(); err != nil {
		t.Fatalf("failed to start node2: %v", err)
	}
	defer node2.Stop()

	peerAddr2 := fmt.Sprintf("127.0.0.1:%d", node2.Port())

	for i := 0; i < 5; i++ {
		recvCh := make(chan time.Time, 1)
		entityKey := fmt.Sprintf("latency-entity-%d", i)

		node2.RegisterHandler(entityKey, func(ctx context.Context, entityType string, payload []byte) error {
			recvCh <- time.Now()
			return nil
		})

		t0 := time.Now()
		payload := []byte(fmt.Sprintf(`{"seq": %d, "timestamp": %d}`, i, t0.UnixNano()))
		if err := node1.BroadcastState(ctx, entityKey, payload, []string{peerAddr2}); err != nil {
			t.Fatalf("iteration %d broadcast failed: %v", i, err)
		}

		select {
		case tRecv := <-recvCh:
			syncDelay := tRecv.Sub(t0)
			t.Logf("Iteration %d -> gRPC state replication delay: %v", i+1, syncDelay)
			if syncDelay >= 50*time.Millisecond {
				t.Fatalf("VIOLATION: gRPC sync delay %v exceeded 50ms requirement", syncDelay)
			}
		case <-time.After(50 * time.Millisecond):
			t.Fatalf("VIOLATION: gRPC sync message not received within 50ms timeout")
		}
	}
}
