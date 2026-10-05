package bifrost

import (
	"context"
	"sort"
	"strings"
	"sync/atomic"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
)

// Streaming for provider-injected tools. One client stream spans several upstream
// streams: each turn's text streams to the client live, injected tool calls are held
// back and executed between turns, and only the last turn ends the client stream.
//
// The state below lives on the session, owned by the goroutines of one client stream,
// never on the BifrostContext (stream-sized data stays out of ctx).

// streamEmit is one chunk to send to the client. terminal marks the chunk that ends the
// client stream; it is the only one post-hooks see as the final chunk.
type streamEmit struct {
	resp     *schemas.BifrostChatResponse
	terminal bool
}

// streamedCall accumulates one tool call's deltas within a turn.
type streamedCall struct {
	index        uint16
	id           *string
	callType     *string
	name         *string
	arguments    strings.Builder
	extraContent []byte
}

func (c *streamedCall) toolCall() schemas.ChatAssistantMessageToolCall {
	call := schemas.ChatAssistantMessageToolCall{
		Index:    c.index,
		ID:       c.id,
		Type:     c.callType,
		Function: schemas.ChatAssistantMessageToolCallFunction{Name: c.name, Arguments: c.arguments.String()},
	}
	if len(c.extraContent) > 0 {
		call.ExtraContent = c.extraContent
	}
	return call
}

// injectedChatStream turns a sequence of upstream chat streams into one client stream.
type injectedChatStream struct {
	set   *injectedToolSet
	depth int // turns started, including the current one

	// Client stream identity, fixed by the first chunk of the first turn.
	id         string
	created    int
	roleSent   bool
	chunkIndex int
	usage      *schemas.BifrostLLMUsage // summed over finished turns

	// Current turn.
	text      strings.Builder
	reasoning strings.Builder
	details   map[int]*schemas.ChatReasoningDetails
	calls     map[uint16]*streamedCall
	finish    *string
	turnUsage *schemas.BifrostLLMUsage
	more      bool // set on the turn's final chunk: injected calls are pending
}

func newInjectedChatStream(set *injectedToolSet) *injectedChatStream {
	return &injectedChatStream{set: set, depth: 1}
}

// onChunk takes one upstream chunk and returns what the client should see. final is
// true for the last chunk of the upstream stream.
func (s *injectedChatStream) onChunk(resp *schemas.BifrostChatResponse, final bool) []streamEmit {
	if s.id == "" {
		s.id, s.created = resp.ID, resp.Created
	}
	if resp.Usage != nil {
		s.turnUsage = resp.Usage
	}
	var visible *schemas.ChatStreamResponseChoiceDelta
	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		if choice.FinishReason != nil {
			s.finish = choice.FinishReason
		}
		if choice.ChatStreamResponseChoice != nil && choice.Delta != nil {
			visible = s.absorbDelta(choice.Delta)
		}
	}

	var emits []streamEmit
	if visible != nil {
		emits = append(emits, streamEmit{resp: s.clientChunk(resp, visible, nil)})
	}
	if !final {
		return emits
	}

	var injected, client []schemas.ChatAssistantMessageToolCall
	for _, call := range s.orderedCalls() {
		if call.name != nil && s.set.isInjected(*call.name) {
			injected = append(injected, call.toolCall())
		} else {
			client = append(client, call.toolCall())
		}
	}
	if len(injected) > 0 && s.depth < s.set.maxDepth {
		s.more = true
		return emits
	}
	s.more = false

	finish := s.finish
	if len(injected) > 0 && len(client) == 0 {
		finish = new(string(schemas.BifrostFinishReasonStop))
	}
	terminal := s.clientChunk(resp, &schemas.ChatStreamResponseChoiceDelta{ToolCalls: client}, finish)
	terminal.Usage = schemas.MergeBifrostLLMUsage(s.usage, s.turnUsage)
	return append(emits, streamEmit{resp: terminal, terminal: true})
}

// absorbDelta records the delta for the turn and returns its client-visible part, or
// nil when it carries nothing the client should see now. Every tool call is held:
// whether a call is injected is only known from its name, and a client call can stream
// before an injected one in the same turn, which must then be dropped.
func (s *injectedChatStream) absorbDelta(delta *schemas.ChatStreamResponseChoiceDelta) *schemas.ChatStreamResponseChoiceDelta {
	for _, call := range delta.ToolCalls {
		s.absorbCall(call)
	}
	if delta.Content != nil {
		s.text.WriteString(*delta.Content)
	}
	if delta.Reasoning != nil {
		s.reasoning.WriteString(*delta.Reasoning)
	}
	for _, detail := range delta.ReasoningDetails {
		s.absorbReasoningDetail(detail)
	}

	visible := *delta
	visible.ToolCalls = nil
	if visible.Role != nil {
		if s.roleSent {
			visible.Role = nil
		}
		s.roleSent = true
	}
	if visible.Role == nil && visible.Content == nil && visible.Refusal == nil && visible.Audio == nil &&
		visible.Reasoning == nil && len(visible.ReasoningDetails) == 0 && len(visible.Annotations) == 0 && len(visible.ExtraContent) == 0 {
		return nil
	}
	return &visible
}

func (s *injectedChatStream) absorbCall(delta schemas.ChatAssistantMessageToolCall) {
	if s.calls == nil {
		s.calls = make(map[uint16]*streamedCall)
	}
	call, ok := s.calls[delta.Index]
	if !ok {
		call = &streamedCall{index: delta.Index}
		s.calls[delta.Index] = call
	}
	if delta.ID != nil && *delta.ID != "" {
		call.id = delta.ID
	}
	if delta.Type != nil {
		call.callType = delta.Type
	}
	if delta.Function.Name != nil && *delta.Function.Name != "" {
		call.name = delta.Function.Name
	}
	call.arguments.WriteString(delta.Function.Arguments)
	if len(delta.ExtraContent) > 0 {
		call.extraContent = delta.ExtraContent
	}
}

// absorbReasoningDetail merges reasoning detail fragments by index, so a thinking
// block and the signature that arrives after it replay as one block.
func (s *injectedChatStream) absorbReasoningDetail(fragment schemas.ChatReasoningDetails) {
	if s.details == nil {
		s.details = make(map[int]*schemas.ChatReasoningDetails)
	}
	detail, ok := s.details[fragment.Index]
	if !ok {
		cp := fragment
		s.details[fragment.Index] = &cp
		return
	}
	appendStr := func(dst **string, add *string) {
		if add == nil {
			return
		}
		if *dst == nil {
			*dst = new(*add)
			return
		}
		*dst = new(**dst + *add)
	}
	appendStr(&detail.Text, fragment.Text)
	appendStr(&detail.Summary, fragment.Summary)
	appendStr(&detail.Data, fragment.Data)
	if fragment.Signature != nil {
		detail.Signature = fragment.Signature
	}
	if fragment.ID != nil {
		detail.ID = fragment.ID
	}
	if fragment.Type != "" {
		detail.Type = fragment.Type
	}
}

func (s *injectedChatStream) orderedCalls() []*streamedCall {
	calls := make([]*streamedCall, 0, len(s.calls))
	for _, call := range s.calls {
		calls = append(calls, call)
	}
	sort.Slice(calls, func(i, j int) bool { return calls[i].index < calls[j].index })
	return calls
}

// clientChunk builds a client chunk from an upstream one: the first turn's id and
// creation time, the running chunk index, and the given delta and finish reason.
func (s *injectedChatStream) clientChunk(upstream *schemas.BifrostChatResponse, delta *schemas.ChatStreamResponseChoiceDelta, finish *string) *schemas.BifrostChatResponse {
	out := *upstream
	out.ID = s.id
	out.Created = s.created
	out.Usage = nil
	out.ExtraFields.ChunkIndex = s.chunkIndex
	out.ExtraFields.RawResponse = nil
	s.chunkIndex++
	out.Choices = []schemas.BifrostResponseChoice{{
		FinishReason:             finish,
		ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: delta},
	}}
	return &out
}

// continues reports whether the turn that just ended left injected calls to execute.
func (s *injectedChatStream) continues() bool {
	return s.more
}

// endTurn closes the turn that just ended with injected calls pending. It returns the
// assistant message to replay, carrying only the injected calls, and those calls.
func (s *injectedChatStream) endTurn() (schemas.ChatMessage, []schemas.ChatAssistantMessageToolCall) {
	var injected []schemas.ChatAssistantMessageToolCall
	for _, call := range s.orderedCalls() {
		if call.name != nil && s.set.isInjected(*call.name) {
			injected = append(injected, call.toolCall())
		}
	}
	assistant := schemas.ChatMessage{
		Role:                 schemas.ChatMessageRoleAssistant,
		ChatAssistantMessage: &schemas.ChatAssistantMessage{ToolCalls: injected},
	}
	if s.text.Len() > 0 {
		assistant.Content = &schemas.ChatMessageContent{ContentStr: new(s.text.String())}
	}
	if s.reasoning.Len() > 0 {
		assistant.Reasoning = new(s.reasoning.String())
	}
	if len(s.details) > 0 {
		indexes := make([]int, 0, len(s.details))
		for index := range s.details {
			indexes = append(indexes, index)
		}
		sort.Ints(indexes)
		for _, index := range indexes {
			assistant.ReasoningDetails = append(assistant.ReasoningDetails, *s.details[index])
		}
	}

	s.usage = schemas.MergeBifrostLLMUsage(s.usage, s.turnUsage)
	s.depth++
	s.text.Reset()
	s.reasoning.Reset()
	s.details = nil
	s.calls = nil
	s.finish = nil
	s.turnUsage = nil
	s.more = false
	return assistant, injected
}

// injectedStreamSkip tells the provider not to send a chunk itself: the session has
// already sent whatever the client should see for it.
var injectedStreamSkip = &schemas.BifrostError{StreamControl: &schemas.StreamControl{SkipStream: new(true)}}

// sendThroughPostHooks runs a client chunk through the real post-hook runner and sends
// it, the way providerUtils.ProcessAndSendResponse does for an ordinary stream.
func sendThroughPostHooks(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, result *schemas.BifrostResponse, bifrostErr *schemas.BifrostError, out chan *schemas.BifrostStreamChunk) {
	processed, processedErr := postHookRunner(ctx, result, bifrostErr)
	if providerUtils.HandleStreamControlSkip(processedErr) {
		return
	}
	providerUtils.GateSendChunk(ctx, providerUtils.BuildClientStreamChunk(ctx, processed, processedErr), out)
}

// resetStreamTurnState clears the per-stream flags the previous upstream stream left on
// the shared context, as the retry path does between attempts. The provider releases
// its response (claiming BifrostContextKeyConnectionClosed) before it closes its
// channel, so once the channel has drained these flags describe a dead stream; left in
// place, the next turn's reader would see its own fresh stream as already closed.
func resetStreamTurnState(ctx *schemas.BifrostContext) {
	ctx.SetValue(schemas.BifrostContextKeyStreamEndIndicator, false)
	ctx.ClearValue(schemas.BifrostContextKeyConnectionClosed)
	ctx.ClearValue(schemas.BifrostContextKeyStreamBodyExhausted)
	ctx.ClearValue(schemas.BifrostContextKeyStreamParkedAfterFinish)
}

// clientEmit is one chunk the session sends to the client.
type clientEmit struct {
	result   *schemas.BifrostResponse
	terminal bool
}

// injectedStreamTurns adapts one API's stream session to chainInjectedStream.
type injectedStreamTurns struct {
	// process returns what the client sees for one upstream chunk; ok is false for a
	// chunk this API does not carry, which is passed through unchanged.
	process func(result *schemas.BifrostResponse, final bool) (emits []clientEmit, ok bool)
	// continues reports whether the turn that just ended has injected calls pending.
	continues func() bool
	// advance executes the pending injected calls and prepares the next turn's request.
	advance func()
	// dispatch opens the current turn's upstream stream.
	dispatch func(runner schemas.PostHookRunner, finalizer func(context.Context)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError)
}

// chainInjectedStream serves one streaming attempt whose provider injects tools. It
// returns the client channel at once; a goroutine chains upstream turns into it until
// a turn ends without injected calls.
//
// The session runs inside the provider's post-hook runner, which the provider calls in
// order with its own StreamEndIndicator writes. For every upstream chunk it sends what
// the client should see (zero or more chunks) through the real post hooks, then tells
// the provider to skip the chunk. Post hooks therefore see exactly the client stream:
// one final chunk, carrying usage for every turn.
//
// Providers call the finalizer they are given when their stream ends. Each turn gets
// one that does nothing until the client stream has ended, because the real finalizer
// releases the plugin pipeline that later turns still run chunks through.
func chainInjectedStream(ctx *schemas.BifrostContext, turns injectedStreamTurns, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	out := make(chan *schemas.BifrostStreamChunk, schemas.DefaultStreamBufferSize)
	var ended atomic.Bool

	runner := func(c *schemas.BifrostContext, result *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
		if bifrostErr != nil || result == nil {
			if bifrostErr != nil {
				ended.Store(true)
			}
			sendThroughPostHooks(c, postHookRunner, result, bifrostErr, out)
			return nil, injectedStreamSkip
		}
		final := IsFinalChunk(c)
		emits, ok := turns.process(result, final)
		if !ok {
			sendThroughPostHooks(c, postHookRunner, result, nil, out)
			return nil, injectedStreamSkip
		}
		for _, emit := range emits {
			c.SetValue(schemas.BifrostContextKeyStreamEndIndicator, emit.terminal)
			if emit.terminal {
				ended.Store(true)
			}
			sendThroughPostHooks(c, postHookRunner, emit.result, nil, out)
		}
		c.SetValue(schemas.BifrostContextKeyStreamEndIndicator, final)
		return nil, injectedStreamSkip
	}
	turnFinalizer := func(c context.Context) {
		if ended.Load() {
			postHookSpanFinalizer(c)
		}
	}

	upstream, bifrostErr := turns.dispatch(runner, turnFinalizer)
	if bifrostErr != nil {
		return nil, bifrostErr
	}

	go func() {
		defer func() {
			providerUtils.CloseStream(ctx, out)
			postHookSpanFinalizer(ctx)
		}()
		for {
			// The session sends everything itself; anything a provider sent directly
			// (outside its post-hook runner) is forwarded unchanged.
			for chunk := range upstream {
				if chunk != nil {
					providerUtils.GateSendChunk(ctx, chunk, out)
				}
			}
			if ended.Load() || !turns.continues() || ctx.Err() != nil {
				return
			}
			resetStreamTurnState(ctx)
			turns.advance()
			upstream, bifrostErr = turns.dispatch(runner, turnFinalizer)
			if bifrostErr != nil {
				ctx.SetValue(schemas.BifrostContextKeyStreamEndIndicator, true)
				ended.Store(true)
				sendThroughPostHooks(ctx, postHookRunner, nil, bifrostErr, out)
				return
			}
		}
	}()
	return out, nil
}

// startInjectedChatStream serves a streaming chat attempt whose provider injects tools.
func (bifrost *Bifrost) startInjectedChatStream(ctx *schemas.BifrostContext, provider schemas.Provider, config *schemas.ProviderConfig, key schemas.Key, original *schemas.BifrostChatRequest, set *injectedToolSet, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	session := newInjectedChatStream(set)
	turn := applyInjectedToolsChat(original, set)
	return chainInjectedStream(ctx, injectedStreamTurns{
		process: func(result *schemas.BifrostResponse, final bool) ([]clientEmit, bool) {
			if result.ChatResponse == nil {
				return nil, false
			}
			var emits []clientEmit
			for _, emit := range session.onChunk(result.ChatResponse, final) {
				emits = append(emits, clientEmit{result: &schemas.BifrostResponse{ChatResponse: emit.resp}, terminal: emit.terminal})
			}
			return emits, true
		},
		continues: session.continues,
		advance: func() {
			assistant, injected := session.endTurn()
			results := executeInjectedCalls(injected, func(call schemas.ChatAssistantMessageToolCall) *schemas.ChatMessage {
				return bifrost.executeInjectedCall(ctx, call)
			})
			next := *turn
			next.Input = make([]schemas.ChatMessage, 0, len(turn.Input)+1+len(results))
			next.Input = append(next.Input, turn.Input...)
			next.Input = append(next.Input, assistant)
			for _, result := range results {
				next.Input = append(next.Input, *result)
			}
			turn = &next
		},
		dispatch: func(runner schemas.PostHookRunner, finalizer func(context.Context)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
			return bifrost.dispatchChatStream(ctx, provider, config, key, turn, runner, finalizer)
		},
	}, postHookRunner, postHookSpanFinalizer)
}

// startInjectedResponsesStream serves a streaming Responses attempt whose provider
// injects tools.
func (bifrost *Bifrost) startInjectedResponsesStream(ctx *schemas.BifrostContext, provider schemas.Provider, config *schemas.ProviderConfig, key schemas.Key, original *schemas.BifrostResponsesRequest, set *injectedToolSet, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	session := newInjectedResponsesStream(set)
	turn := applyInjectedToolsResponses(original, set)
	return chainInjectedStream(ctx, injectedStreamTurns{
		process: func(result *schemas.BifrostResponse, final bool) ([]clientEmit, bool) {
			if result.ResponsesStreamResponse == nil {
				return nil, false
			}
			var emits []clientEmit
			for _, emit := range session.onEvent(result.ResponsesStreamResponse, final) {
				emits = append(emits, clientEmit{result: &schemas.BifrostResponse{ResponsesStreamResponse: emit.event}, terminal: emit.terminal})
			}
			return emits, true
		},
		continues: session.continues,
		advance: func() {
			items, injected := session.endTurn()
			results := executeInjectedCalls(injected, func(call schemas.ChatAssistantMessageToolCall) *schemas.ChatMessage {
				return bifrost.executeInjectedCall(ctx, call)
			})
			next := *turn
			next.Input = make([]schemas.ResponsesMessage, 0, len(turn.Input)+len(items)+len(results))
			next.Input = append(next.Input, turn.Input...)
			next.Input = append(next.Input, items...)
			for _, result := range results {
				next.Input = append(next.Input, result.ToResponsesMessages()...)
			}
			turn = &next
		},
		dispatch: func(runner schemas.PostHookRunner, finalizer func(context.Context)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
			return bifrost.dispatchResponsesStream(ctx, provider, config, key, turn, runner, finalizer)
		},
	}, postHookRunner, postHookSpanFinalizer)
}

// responsesEmit is one Responses stream event to send to the client.
type responsesEmit struct {
	event    *schemas.BifrostResponsesStreamResponse
	terminal bool
}

// itemRoute is what happens to one upstream output item's events.
type itemRoute int

const (
	routeVisible  itemRoute = iota // forwarded live with a client output index
	routeClient                    // a client function call: held until the turn shows no injected call
	routeInjected                  // an injected function call: never reaches the client
	routeDropped                   // a client call in a turn that also calls an injected tool
)

// injectedResponsesStream is the Responses API parallel of injectedChatStream. The
// client sees one response: the first turn's response.created, items from every turn
// under consecutive output indexes, sequence numbers without gaps, and one
// response.completed whose output and usage cover all turns.
type injectedResponsesStream struct {
	set   *injectedToolSet
	depth int

	responseID  *string
	createdSent bool
	seq         int
	nextIndex   int
	usage       *schemas.BifrostLLMUsage
	output      []schemas.ResponsesMessage // completed client-visible items, all turns

	// Current turn.
	routes      map[int]itemRoute
	indexes     map[int]int // upstream output index -> client output index
	itemRoutes  map[string]int
	held        []*schemas.BifrostResponsesStreamResponse
	heldItems   []schemas.ResponsesMessage
	replay      []schemas.ResponsesMessage // completed items to send back as next turn's input
	injected    []schemas.ChatAssistantMessageToolCall
	hasInjected bool
	more        bool
}

func newInjectedResponsesStream(set *injectedToolSet) *injectedResponsesStream {
	return &injectedResponsesStream{set: set, depth: 1}
}

// onEvent takes one upstream event and returns the events the client should see.
func (s *injectedResponsesStream) onEvent(ev *schemas.BifrostResponsesStreamResponse, final bool) []responsesEmit {
	switch ev.Type {
	case schemas.ResponsesStreamResponseTypeCreated, schemas.ResponsesStreamResponseTypeInProgress, schemas.ResponsesStreamResponseTypeQueued:
		if ev.Type == schemas.ResponsesStreamResponseTypeCreated && s.responseID == nil && ev.Response != nil {
			s.responseID = ev.Response.ID
		}
		if s.createdSent && ev.Type != schemas.ResponsesStreamResponseTypeQueued {
			return nil
		}
		if ev.Type == schemas.ResponsesStreamResponseTypeCreated {
			s.createdSent = true
		}
		return []responsesEmit{{event: s.renumber(ev, nil)}}
	case schemas.ResponsesStreamResponseTypeCompleted, schemas.ResponsesStreamResponseTypeIncomplete:
		return s.onTurnEnd(ev)
	case schemas.ResponsesStreamResponseTypeFailed, schemas.ResponsesStreamResponseTypeError:
		return []responsesEmit{{event: s.renumber(ev, nil), terminal: true}}
	}

	upstreamIndex, route, known := s.routeOf(ev)
	if !known {
		return []responsesEmit{{event: s.renumber(ev, nil), terminal: final}}
	}
	if ev.Type == schemas.ResponsesStreamResponseTypeOutputItemDone && ev.Item != nil {
		s.recordDone(route, *ev.Item)
	}
	switch route {
	case routeVisible:
		index := s.indexes[upstreamIndex]
		return []responsesEmit{{event: s.renumber(ev, &index)}}
	case routeClient:
		s.held = append(s.held, ev)
	}
	return nil
}

// routeOf classifies the item an event belongs to, registering it on output_item.added.
func (s *injectedResponsesStream) routeOf(ev *schemas.BifrostResponsesStreamResponse) (int, itemRoute, bool) {
	if s.routes == nil {
		s.routes, s.indexes, s.itemRoutes = map[int]itemRoute{}, map[int]int{}, map[string]int{}
	}
	if ev.Type == schemas.ResponsesStreamResponseTypeOutputItemAdded && ev.OutputIndex != nil && ev.Item != nil {
		index := *ev.OutputIndex
		route := routeVisible
		if isFunctionCall(*ev.Item) {
			switch {
			case ev.Item.Name != nil && s.set.isInjected(*ev.Item.Name):
				route = routeInjected
				s.dropClientCalls()
			case s.hasInjected:
				route = routeDropped
			default:
				route = routeClient
			}
		}
		s.routes[index] = route
		if route == routeVisible {
			s.indexes[index] = s.nextIndex
			s.nextIndex++
		}
		if ev.Item.ID != nil {
			s.itemRoutes[*ev.Item.ID] = index
		}
		return index, route, true
	}
	if ev.OutputIndex != nil {
		route, ok := s.routes[*ev.OutputIndex]
		return *ev.OutputIndex, route, ok
	}
	if ev.ItemID != nil {
		if index, ok := s.itemRoutes[*ev.ItemID]; ok {
			return index, s.routes[index], true
		}
	}
	return 0, 0, false
}

// dropClientCalls discards the client calls held so far in this turn: the turn calls
// an injected tool, so it is re-asked and the client calls in it are never answered.
func (s *injectedResponsesStream) dropClientCalls() {
	s.hasInjected = true
	for index, route := range s.routes {
		if route == routeClient {
			s.routes[index] = routeDropped
		}
	}
	s.held = nil
	s.heldItems = nil
}

func (s *injectedResponsesStream) recordDone(route itemRoute, item schemas.ResponsesMessage) {
	switch route {
	case routeVisible:
		s.output = append(s.output, item)
		s.replay = append(s.replay, item)
	case routeInjected:
		s.replay = append(s.replay, item)
		if call, ok := injectedResponsesCall(item, s.set); ok {
			s.injected = append(s.injected, call)
		}
	case routeClient:
		s.heldItems = append(s.heldItems, item)
	}
}

// onTurnEnd handles response.completed (or incomplete) for one upstream turn.
func (s *injectedResponsesStream) onTurnEnd(ev *schemas.BifrostResponsesStreamResponse) []responsesEmit {
	var turnUsage *schemas.BifrostLLMUsage
	if ev.Response != nil {
		turnUsage = ev.Response.Usage.ToBifrostLLMUsage()
	}
	s.usage = schemas.MergeBifrostLLMUsage(s.usage, turnUsage)
	if len(s.injected) > 0 && s.depth < s.set.maxDepth {
		s.more = true
		return nil
	}
	s.more = false

	var emits []responsesEmit
	for _, held := range s.held {
		index := held.OutputIndex
		if index != nil {
			upstream := *index
			if _, ok := s.indexes[upstream]; !ok {
				s.indexes[upstream] = s.nextIndex
				s.nextIndex++
			}
			index = new(s.indexes[upstream])
		}
		emits = append(emits, responsesEmit{event: s.renumber(held, index)})
	}
	s.output = append(s.output, s.heldItems...)

	terminal := s.renumber(ev, nil)
	response := schemas.BifrostResponsesResponse{}
	if ev.Response != nil {
		response = *ev.Response
	}
	if s.responseID != nil {
		response.ID = s.responseID
	}
	response.Output = s.output
	response.Usage = s.usage.ToResponsesResponseUsage()
	terminal.Response = &response
	return append(emits, responsesEmit{event: terminal, terminal: true})
}

// renumber copies an event with the client's next sequence number and, when given, the
// client output index.
func (s *injectedResponsesStream) renumber(ev *schemas.BifrostResponsesStreamResponse, outputIndex *int) *schemas.BifrostResponsesStreamResponse {
	out := *ev
	out.SequenceNumber = s.seq
	out.ExtraFields.ChunkIndex = s.seq
	out.ExtraFields.RawResponse = nil
	s.seq++
	if outputIndex != nil {
		out.OutputIndex = outputIndex
	}
	return &out
}

// continues reports whether the turn that just ended left injected calls to execute.
func (s *injectedResponsesStream) continues() bool {
	return s.more
}

// endTurn closes a turn that ended with injected calls pending. It returns the items to
// replay as input (the turn's output minus client calls) and the calls to execute.
func (s *injectedResponsesStream) endTurn() ([]schemas.ResponsesMessage, []schemas.ChatAssistantMessageToolCall) {
	replay, injected := s.replay, s.injected
	s.depth++
	s.routes, s.indexes, s.itemRoutes = nil, nil, nil
	s.held, s.heldItems, s.replay, s.injected = nil, nil, nil, nil
	s.hasInjected, s.more = false, false
	return replay, injected
}
