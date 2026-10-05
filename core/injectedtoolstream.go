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

// startInjectedChatStream serves one streaming chat attempt whose provider injects
// tools. It returns the client channel at once; a goroutine chains upstream turns into
// it until a turn ends without injected calls.
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
func (bifrost *Bifrost) startInjectedChatStream(ctx *schemas.BifrostContext, provider schemas.Provider, config *schemas.ProviderConfig, key schemas.Key, original *schemas.BifrostChatRequest, set *injectedToolSet, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context)) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	session := newInjectedChatStream(set)
	out := make(chan *schemas.BifrostStreamChunk, schemas.DefaultStreamBufferSize)
	var ended atomic.Bool

	runner := func(c *schemas.BifrostContext, result *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
		if bifrostErr != nil || result == nil || result.ChatResponse == nil {
			if bifrostErr != nil {
				ended.Store(true)
			}
			sendThroughPostHooks(c, postHookRunner, result, bifrostErr, out)
			return nil, injectedStreamSkip
		}
		final := IsFinalChunk(c)
		for _, emit := range session.onChunk(result.ChatResponse, final) {
			c.SetValue(schemas.BifrostContextKeyStreamEndIndicator, emit.terminal)
			if emit.terminal {
				ended.Store(true)
			}
			sendThroughPostHooks(c, postHookRunner, &schemas.BifrostResponse{ChatResponse: emit.resp}, nil, out)
		}
		c.SetValue(schemas.BifrostContextKeyStreamEndIndicator, final)
		return nil, injectedStreamSkip
	}
	turnFinalizer := func(c context.Context) {
		if ended.Load() {
			postHookSpanFinalizer(c)
		}
	}

	turn := applyInjectedToolsChat(original, set)
	upstream, bifrostErr := bifrost.dispatchChatStream(ctx, provider, config, key, turn, runner, turnFinalizer)
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
			if ended.Load() || !session.continues() || ctx.Err() != nil {
				return
			}
			assistant, injected := session.endTurn()
			resetStreamTurnState(ctx)
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

			upstream, bifrostErr = bifrost.dispatchChatStream(ctx, provider, config, key, turn, runner, turnFinalizer)
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
