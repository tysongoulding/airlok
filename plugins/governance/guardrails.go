package governance

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// GuardrailFinding represents a single detected entity match within evaluated text.
type GuardrailFinding struct {
	RuleID      int               `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	EntityType  string            `json:"entity_type"`
	StartIndex  int               `json:"start_index"`
	EndIndex    int               `json:"end_index"`
	MatchedText string            `json:"matched_text"`
	Action      RedactionAction   `json:"action"`
	Strategy    RedactionStrategy `json:"strategy,omitempty"`
}

// GuardrailResult represents the comprehensive outcome of a guardrail evaluation.
type GuardrailResult struct {
	Allowed            bool               `json:"allowed"`
	Action             RedactionAction    `json:"action"` // "block", "redact", "detect_only"
	ActionTaken        RedactionAction    `json:"action_taken"`
	RuleID             int                `json:"rule_id"`
	RuleName           string             `json:"rule_name"`
	PolicyName         string             `json:"policy_name"`
	Reason             string             `json:"reason,omitempty"`
	InterventionReason string             `json:"intervention_reason,omitempty"`
	Findings           []GuardrailFinding `json:"findings,omitempty"`
	DetectedEntities   []string           `json:"detected_entities,omitempty"`
	TransformedText    string             `json:"transformed_text,omitempty"`
	LiteralMap         map[string]string  `json:"literal_map,omitempty"`    // original -> replacement
	ReversibleMap      map[string]string  `json:"reversible_map,omitempty"` // replacement -> original
	Assessments        []string           `json:"assessments,omitempty"`
	UsageUnits         map[string]int     `json:"usage_units,omitempty"`
	EvaluationLatency  time.Duration      `json:"evaluation_latency"`
}

// GuardrailRule defines a single content guardrail rule.
type GuardrailRule struct {
	ID               int                  `json:"id"`
	Name             string               `json:"name"`
	Enabled          bool                 `json:"enabled"`
	Target           string               `json:"target"` // "llm", "mcp"
	CELExpression    string               `json:"cel_expression,omitempty"`
	ApplyTo          string               `json:"apply_to"` // "input", "output", "both"
	Action           RedactionAction      `json:"action"`   // "block", "redact", "detect_only"
	Strategy         RedactionStrategy    `json:"strategy,omitempty"`
	Mode             RedactionMode        `json:"mode,omitempty"`
	Patterns         []RegexPatternConfig `json:"patterns,omitempty"`
	ProhibitedTopics []string             `json:"prohibited_topics,omitempty"`
	SamplingRate     int                  `json:"sampling_rate,omitempty"` // 0-100, default 100
	CloudAdapter     string               `json:"cloud_adapter,omitempty"` // "bedrock", "azure", "model-armor"
}

// GuardrailEvaluator is the contract for evaluating inbound requests and outbound responses.
type GuardrailEvaluator interface {
	EvaluateInput(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) (*GuardrailResult, error)
	EvaluateOutput(ctx *schemas.BifrostContext, resp *schemas.BifrostResponse) (*GuardrailResult, error)
	EvaluateText(text string, target string, phase string, vars map[string]string) *GuardrailResult
	EvaluateTextWithContext(ctx *schemas.BifrostContext, text string, target string, phase string, vars map[string]string) *GuardrailResult
	EvaluateStream(chunks []string) ([]string, bool, string)
}

// GuardrailsEngine implements GuardrailEvaluator with high-speed in-process RE2 and CEL evaluation.
type GuardrailsEngine struct {
	mu            sync.RWMutex
	rules         []GuardrailRule
	cloudAdapters map[string]CloudGuardrailAdapter
}

// NewGuardrailsEngine initializes an engine with configured rules.
func NewGuardrailsEngine(rules []GuardrailRule) *GuardrailsEngine {
	engine := &GuardrailsEngine{
		rules:         rules,
		cloudAdapters: make(map[string]CloudGuardrailAdapter),
	}
	return engine
}

// DefaultGuardrailsEngine creates an engine initialized with standard enterprise guardrail rules.
func DefaultGuardrailsEngine() *GuardrailsEngine {
	ssnPattern := RegexPatternConfig{
		ID:          1,
		Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
		Description: "US Social Security Number",
		EntityType:  "US_SSN",
		Action:      ActionBlock,
		Strategy:    StrategyReplace,
		Mode:        ModeRuntime,
		Compiled:    regexSSN,
	}

	emailPattern := RegexPatternConfig{
		ID:          2,
		Pattern:     `(?i)\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`,
		Description: "Email address",
		EntityType:  "EMAIL",
		Action:      ActionRedact,
		Strategy:    StrategyReplace,
		Mode:        ModeRuntime,
		Compiled:    regexEmail,
	}

	phonePattern := RegexPatternConfig{
		ID:          3,
		Pattern:     `\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`,
		Description: "US phone number",
		EntityType:  "PHONE_NUMBER",
		Action:      ActionRedact,
		Strategy:    StrategyReplace,
		Mode:        ModeRuntime,
		Compiled:    regexPhone,
	}

	rules := []GuardrailRule{
		{
			ID:       101,
			Name:     "PII Block Policy",
			Enabled:  true,
			Target:   "llm",
			ApplyTo:  "both",
			Action:   ActionBlock,
			Patterns: []RegexPatternConfig{ssnPattern},
		},
		{
			ID:       102,
			Name:     "PII Redaction Policy",
			Enabled:  true,
			Target:   "llm",
			ApplyTo:  "both",
			Action:   ActionRedact,
			Mode:     ModeRuntime,
			Strategy: StrategyReplace,
			Patterns: []RegexPatternConfig{emailPattern, phonePattern},
		},
		{
			ID:               103,
			Name:             "Prohibited Topics Policy",
			Enabled:          true,
			Target:           "llm",
			ApplyTo:          "both",
			Action:           ActionBlock,
			ProhibitedTopics: []string{"classified project x", "insider trading", "exfiltrate private keys"},
		},
		{
			ID:       104,
			Name:     "Secrets Detection Policy",
			Enabled:  true,
			Target:   "llm",
			ApplyTo:  "both",
			Action:   ActionBlock,
			Patterns: BuiltinSecretsTemplates(),
		},
	}

	return NewGuardrailsEngine(rules)
}

// AddRule appends a rule to the engine.
func (e *GuardrailsEngine) AddRule(rule GuardrailRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// RegisterCloudAdapter registers an external cloud safety adapter.
func (e *GuardrailsEngine) RegisterCloudAdapter(name string, adapter CloudGuardrailAdapter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cloudAdapters[name] = adapter
}

// EvaluateInput inspects request text and applies guardrail rules.
func (e *GuardrailsEngine) EvaluateInput(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) (*GuardrailResult, error) {
	if e == nil || req == nil {
		return nil, nil
	}

	text := extractRequestText(req)
	vars := extractContextVars(ctx, req)
	target := "llm"
	if req.RequestType == schemas.MCPToolExecutionRequest {
		target = "mcp"
	}

	res := e.EvaluateTextWithContext(ctx, text, target, "input", vars)
	return res, nil
}

// EvaluateOutput inspects completion text and applies guardrail rules.
func (e *GuardrailsEngine) EvaluateOutput(ctx *schemas.BifrostContext, resp *schemas.BifrostResponse) (*GuardrailResult, error) {
	if e == nil || resp == nil {
		return nil, nil
	}

	text := extractResponseText(resp)
	vars := make(map[string]string)
	if ctx != nil {
		if vk := bifrostGetString(ctx, schemas.BifrostContextKeyVirtualKey); vk != "" {
			vars["virtual_key"] = vk
		}
	}

	res := e.EvaluateTextWithContext(ctx, text, "llm", "output", vars)
	return res, nil
}

// EvaluateText inspects plain text against configured rules.
func (e *GuardrailsEngine) EvaluateText(text string, target string, phase string, vars map[string]string) *GuardrailResult {
	return e.EvaluateTextWithContext(nil, text, target, phase, vars)
}

// EvaluateTextWithContext inspects plain text against configured rules and cloud adapters with context propagation.
func (e *GuardrailsEngine) EvaluateTextWithContext(ctx *schemas.BifrostContext, text string, target string, phase string, vars map[string]string) *GuardrailResult {
	start := time.Now()

	result := &GuardrailResult{
		Allowed:           true,
		Action:            ActionDetectOnly,
		ActionTaken:       ActionDetectOnly,
		TransformedText:   text,
		LiteralMap:        make(map[string]string),
		ReversibleMap:     make(map[string]string),
		EvaluationLatency: 0,
	}

	if text == "" {
		result.EvaluationLatency = time.Since(start)
		return result
	}

	if ctx == nil {
		ctx = schemas.NewBifrostContext(nil, time.Time{})
	}

	// 1. Thread-safe snapshot of rules and adapters without holding lock during execution
	e.mu.RLock()
	rules := make([]GuardrailRule, len(e.rules))
	copy(rules, e.rules)
	adapters := make(map[string]CloudGuardrailAdapter, len(e.cloudAdapters))
	for k, v := range e.cloudAdapters {
		adapters[k] = v
	}
	e.mu.RUnlock()

	revCtx := NewReversibleContext()
	currentText := text
	invokedAdapters := make(map[string]bool)

	// Helper to invoke cloud adapter
	invokeAdapter := func(adapterName string, rule *GuardrailRule) bool {
		adapter, ok := adapters[adapterName]
		if !ok || adapter == nil {
			return false
		}
		invokedAdapters[adapterName] = true

		var model, provider string
		if vars != nil {
			model = vars["model"]
			provider = vars["provider"]
		}

		cloudReq := &CloudSafetyRequest{
			Phase:    phase,
			Text:     currentText,
			Model:    model,
			Provider: provider,
			Metadata: vars,
		}

		cloudResp, err := adapter.InspectContent(ctx, cloudReq)
		if err != nil {
			// Fail open on unexpected external cloud error with warning
			return false
		}
		if cloudResp == nil {
			return false
		}

		if !cloudResp.Allowed || cloudResp.ActionTaken == "block" {
			reason := cloudResp.InterventionReason
			if reason == "" {
				reason = fmt.Sprintf("Blocked by cloud adapter: %s", adapterName)
			}
			result.Allowed = false
			result.Action = ActionBlock
			result.ActionTaken = ActionBlock
			if rule != nil {
				result.RuleID = rule.ID
				result.RuleName = rule.Name
				result.PolicyName = rule.Name
			} else {
				result.RuleName = fmt.Sprintf("Cloud Safety - %s", adapterName)
				result.PolicyName = fmt.Sprintf("Cloud Safety Policy (%s)", adapterName)
			}
			result.Reason = reason
			result.InterventionReason = reason
			result.Assessments = append(result.Assessments, cloudResp.Assessments...)
			result.UsageUnits = cloudResp.UsageUnits
			return true // Halted
		}

		if cloudResp.ActionTaken == "redact" && cloudResp.TransformedText != "" && cloudResp.TransformedText != currentText {
			result.LiteralMap[currentText] = cloudResp.TransformedText
			currentText = cloudResp.TransformedText
			result.TransformedText = currentText
			result.ActionTaken = ActionRedact
			if result.Action != ActionBlock {
				result.Action = ActionRedact
			}
			result.Assessments = append(result.Assessments, cloudResp.Assessments...)
		}

		return false
	}

	// 2. Evaluate Guardrail Rules
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.Target != "" && rule.Target != target {
			continue
		}
		if rule.ApplyTo != "" && rule.ApplyTo != "both" && rule.ApplyTo != phase {
			continue
		}
		if rule.SamplingRate > 0 && rule.SamplingRate < 100 {
			if rand.IntN(100) >= rule.SamplingRate {
				continue
			}
		}

		// CEL Expression Evaluation
		if rule.CELExpression != "" {
			matched := EvaluateCELCondition(rule.CELExpression, vars)
			if !matched {
				continue
			}
		}

		// Evaluate Rule-Associated Cloud Adapter
		if rule.CloudAdapter != "" {
			if blocked := invokeAdapter(rule.CloudAdapter, &rule); blocked {
				result.EvaluationLatency = time.Since(start)
				return result
			}
		}

		// A. Prohibited topics check
		for _, topic := range rule.ProhibitedTopics {
			if topic != "" && strings.Contains(strings.ToLower(currentText), strings.ToLower(topic)) {
				result.Allowed = false
				result.Action = ActionBlock
				result.ActionTaken = ActionBlock
				result.RuleID = rule.ID
				result.RuleName = rule.Name
				result.PolicyName = rule.Name
				reason := fmt.Sprintf("Prohibited topic detected: %s", topic)
				result.Reason = reason
				result.InterventionReason = reason
				result.DetectedEntities = append(result.DetectedEntities, "PROHIBITED_TOPIC")
				result.Findings = append(result.Findings, GuardrailFinding{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					EntityType:  "PROHIBITED_TOPIC",
					MatchedText: topic,
					Action:      ActionBlock,
				})
				result.EvaluationLatency = time.Since(start)
				return result
			}
		}

		// B. Pattern Matching (Regex)
		patterns := rule.Patterns
		if len(patterns) == 0 {
			continue
		}

		// Ensure pattern actions and strategies inherit from rule if not set
		resolvedPatterns := make([]RegexPatternConfig, len(patterns))
		for i, p := range patterns {
			rp := p
			if rp.Action == "" {
				rp.Action = rule.Action
			}
			if rp.Strategy == "" {
				rp.Strategy = rule.Strategy
			}
			if rp.Mode == "" {
				rp.Mode = rule.Mode
			}
			resolvedPatterns[i] = rp
		}

		spans := FindSpans(resolvedPatterns, currentText)
		if len(spans) == 0 {
			continue
		}

		for _, span := range spans {
			finding := GuardrailFinding{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				EntityType:  span.EntityType,
				StartIndex:  span.Start,
				EndIndex:    span.End,
				MatchedText: span.MatchedText,
				Action:      span.Action,
				Strategy:    span.Strategy,
			}
			result.Findings = append(result.Findings, finding)
			result.DetectedEntities = append(result.DetectedEntities, span.EntityType)

			// If any span action is block, abort immediately with block
			if span.Action == ActionBlock {
				result.Allowed = false
				result.Action = ActionBlock
				result.ActionTaken = ActionBlock
				result.RuleID = rule.ID
				result.RuleName = rule.Name
				result.PolicyName = rule.Name
				reason := fmt.Sprintf("Guardrail violation: [%s] blocked the request (detected %s)", rule.Name, span.EntityType)
				result.Reason = reason
				result.InterventionReason = reason
				result.EvaluationLatency = time.Since(start)
				return result
			}
		}

		// Apply Redactions if rule action is redact
		if rule.Action == ActionRedact {
			result.Action = ActionRedact
			result.ActionTaken = ActionRedact
			result.RuleID = rule.ID
			result.RuleName = rule.Name
			result.PolicyName = rule.Name

			runtimeText, _, litMap, revMap := RedactText(currentText, spans, revCtx)
			currentText = runtimeText
			for k, v := range litMap {
				result.LiteralMap[k] = v
			}
			for k, v := range revMap {
				result.ReversibleMap[k] = v
			}
		}
	}

	// 3. Standalone Registered Cloud Adapters (not bound to specific rule)
	if target == "llm" || target == "" {
		for name := range adapters {
			if !invokedAdapters[name] {
				if blocked := invokeAdapter(name, nil); blocked {
					result.EvaluationLatency = time.Since(start)
					return result
				}
			}
		}
	}

	result.TransformedText = currentText
	result.EvaluationLatency = time.Since(start)
	return result
}

// EvaluateStream evaluates a sequence of stream chunks.
// Clean chunks pass through; if a sensitive entity with ActionBlock is encountered,
// the stream is halted immediately.
func (e *GuardrailsEngine) EvaluateStream(chunks []string) ([]string, bool, string) {
	var accumulated strings.Builder
	var emitted []string

	for _, chunk := range chunks {
		accumulated.WriteString(chunk)
		fullText := accumulated.String()

		res := e.EvaluateText(fullText, "llm", "output", nil)
		if !res.Allowed {
			return emitted, true, res.InterventionReason
		}
		emitted = append(emitted, chunk)
	}

	return emitted, false, ""
}

// ============================================================================
// Fast In-Process CEL Condition Evaluator
// ============================================================================

// EvaluateCELCondition evaluates boolean CEL expressions like:
//
//	model == "gpt-4o"
//	provider == "openai"
//	headers["x-dept"] == "finance"
//	user == "alice" && model.startsWith("gpt-")
func EvaluateCELCondition(expr string, vars map[string]string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}

	// Handle top-level logical OR: expr1 || expr2
	orParts := splitLogicalOp(expr, "||")
	if len(orParts) > 1 {
		for _, part := range orParts {
			if EvaluateCELCondition(part, vars) {
				return true
			}
		}
		return false
	}

	// Handle top-level logical AND: expr1 && expr2
	andParts := splitLogicalOp(expr, "&&")
	if len(andParts) > 1 {
		for _, part := range andParts {
			if !EvaluateCELCondition(part, vars) {
				return false
			}
		}
		return true
	}

	// Handle negation: !expr
	if strings.HasPrefix(expr, "!") {
		return !EvaluateCELCondition(strings.TrimSpace(expr[1:]), vars)
	}

	// Handle parentheses: (expr)
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		// Verify matching outer parens
		if isMatchingOuterParen(expr) {
			return EvaluateCELCondition(expr[1:len(expr)-1], vars)
		}
	}

	// Comparison operators: ==, !=, in
	if strings.Contains(expr, "==") {
		parts := strings.SplitN(expr, "==", 2)
		left := resolveCELValue(strings.TrimSpace(parts[0]), vars)
		right := resolveCELValue(strings.TrimSpace(parts[1]), vars)
		return left == right
	}
	if strings.Contains(expr, "!=") {
		parts := strings.SplitN(expr, "!=", 2)
		left := resolveCELValue(strings.TrimSpace(parts[0]), vars)
		right := resolveCELValue(strings.TrimSpace(parts[1]), vars)
		return left != right
	}

	// Method calls: var.startsWith("prefix"), var.endsWith("suffix"), var.contains("sub")
	if strings.Contains(expr, ".startsWith(") {
		return evalStringMethod(expr, ".startsWith(", strings.HasPrefix, vars)
	}
	if strings.Contains(expr, ".endsWith(") {
		return evalStringMethod(expr, ".endsWith(", strings.HasSuffix, vars)
	}
	if strings.Contains(expr, ".contains(") {
		return evalStringMethod(expr, ".contains(", strings.Contains, vars)
	}

	// Array membership: var in ["val1", "val2"]
	if strings.Contains(expr, " in ") {
		parts := strings.SplitN(expr, " in ", 2)
		left := resolveCELValue(strings.TrimSpace(parts[0]), vars)
		rawRight := strings.TrimSpace(parts[1])
		if strings.HasPrefix(rawRight, "[") && strings.HasSuffix(rawRight, "]") {
			items := strings.Split(rawRight[1:len(rawRight)-1], ",")
			for _, it := range items {
				clean := unquoteString(strings.TrimSpace(it))
				if left == clean {
					return true
				}
			}
		}
		return false
	}

	// Direct boolean variable
	val := resolveCELValue(expr, vars)
	return val == "true"
}

func evalStringMethod(expr, method string, fn func(s, substr string) bool, vars map[string]string) bool {
	idx := strings.Index(expr, method)
	if idx < 0 {
		return false
	}
	varName := strings.TrimSpace(expr[:idx])
	targetVal := resolveCELValue(varName, vars)

	argStart := idx + len(method)
	argEnd := strings.LastIndex(expr, ")")
	if argEnd <= argStart {
		return false
	}
	arg := unquoteString(strings.TrimSpace(expr[argStart:argEnd]))
	return fn(targetVal, arg)
}

func resolveCELValue(token string, vars map[string]string) string {
	token = strings.TrimSpace(token)
	// Quoted string literal
	if (strings.HasPrefix(token, `"`) && strings.HasSuffix(token, `"`)) ||
		(strings.HasPrefix(token, `'`) && strings.HasSuffix(token, `'`)) {
		return unquoteString(token)
	}

	// Map lookup: headers["x-header"] or headers['x-header']
	if strings.HasPrefix(token, "headers[") && strings.HasSuffix(token, "]") {
		key := unquoteString(token[8 : len(token)-1])
		if vars != nil {
			if v, ok := vars["header:"+strings.ToLower(key)]; ok {
				return v
			}
			if v, ok := vars[key]; ok {
				return v
			}
		}
		return ""
	}

	// Dotted access: headers.key
	if strings.HasPrefix(token, "headers.") {
		key := token[8:]
		if vars != nil {
			if v, ok := vars["header:"+strings.ToLower(key)]; ok {
				return v
			}
			if v, ok := vars[key]; ok {
				return v
			}
		}
		return ""
	}

	// Direct variable
	if vars != nil {
		if v, ok := vars[token]; ok {
			return v
		}
	}
	return token
}

func unquoteString(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			unq, err := strconv.Unquote(`"` + s[1:len(s)-1] + `"`)
			if err == nil {
				return unq
			}
			return s[1 : len(s)-1]
		}
	}
	return s
}

func splitLogicalOp(expr, op string) []string {
	var parts []string
	parenDepth := 0
	inQuote := false
	quoteChar := byte(0)
	lastIdx := 0

	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if !inQuote && (c == '"' || c == '\'') {
			inQuote = true
			quoteChar = c
			continue
		}
		if inQuote && c == quoteChar {
			inQuote = false
			continue
		}
		if inQuote {
			continue
		}

		if c == '(' {
			parenDepth++
		} else if c == ')' {
			parenDepth--
		}

		if parenDepth == 0 && i+len(op) <= len(expr) && expr[i:i+len(op)] == op {
			parts = append(parts, strings.TrimSpace(expr[lastIdx:i]))
			lastIdx = i + len(op)
			i += len(op) - 1
		}
	}
	if lastIdx < len(expr) {
		parts = append(parts, strings.TrimSpace(expr[lastIdx:]))
	}
	return parts
}

func isMatchingOuterParen(s string) bool {
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return false
	}
	depth := 0
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
			if depth == 0 {
				return false
			}
		}
	}
	return depth == 1
}

// ============================================================================
// Helper extraction methods
// ============================================================================

func extractRequestText(req *schemas.BifrostRequest) string {
	if req == nil {
		return ""
	}
	if req.ChatRequest != nil {
		var sb strings.Builder
		for _, msg := range req.ChatRequest.Input {
			if msg.Content != nil {
				if msg.Content.ContentStr != nil {
					sb.WriteString(*msg.Content.ContentStr)
					sb.WriteString(" ")
				}
				for _, block := range msg.Content.ContentBlocks {
					if block.Text != nil {
						sb.WriteString(*block.Text)
						sb.WriteString(" ")
					}
				}
			}
		}
		return strings.TrimSpace(sb.String())
	}
	if req.TextCompletionRequest != nil && req.TextCompletionRequest.Input != nil {
		if req.TextCompletionRequest.Input.PromptStr != nil {
			return *req.TextCompletionRequest.Input.PromptStr
		}
		if len(req.TextCompletionRequest.Input.PromptArray) > 0 {
			return strings.Join(req.TextCompletionRequest.Input.PromptArray, " ")
		}
	}
	if req.ResponsesRequest != nil {
		var sb strings.Builder
		for _, msg := range req.ResponsesRequest.Input {
			if msg.Content != nil {
				if msg.Content.ContentStr != nil {
					sb.WriteString(*msg.Content.ContentStr)
					sb.WriteString(" ")
				}
				for _, block := range msg.Content.ContentBlocks {
					if block.Text != nil {
						sb.WriteString(*block.Text)
						sb.WriteString(" ")
					}
				}
			}
		}
		return strings.TrimSpace(sb.String())
	}
	return ""
}

func extractResponseText(resp *schemas.BifrostResponse) string {
	if resp == nil {
		return ""
	}
	if resp.ChatResponse != nil {
		var sb strings.Builder
		for _, c := range resp.ChatResponse.Choices {
			if c.Message != nil && c.Message.Content != nil {
				if c.Message.Content.ContentStr != nil {
					sb.WriteString(*c.Message.Content.ContentStr)
					sb.WriteString(" ")
				}
				for _, block := range c.Message.Content.ContentBlocks {
					if block.Text != nil {
						sb.WriteString(*block.Text)
						sb.WriteString(" ")
					}
				}
			}
		}
		return strings.TrimSpace(sb.String())
	}
	if resp.TextCompletionResponse != nil {
		var sb strings.Builder
		for _, c := range resp.TextCompletionResponse.Choices {
			if c.Text != nil {
				sb.WriteString(*c.Text)
				sb.WriteString(" ")
			}
		}
		return strings.TrimSpace(sb.String())
	}
	if resp.ResponsesResponse != nil {
		var sb strings.Builder
		for _, msg := range resp.ResponsesResponse.Output {
			if msg.Content != nil {
				if msg.Content.ContentStr != nil {
					sb.WriteString(*msg.Content.ContentStr)
					sb.WriteString(" ")
				}
				for _, block := range msg.Content.ContentBlocks {
					if block.Text != nil {
						sb.WriteString(*block.Text)
						sb.WriteString(" ")
					}
				}
			}
		}
		return strings.TrimSpace(sb.String())
	}
	return ""
}

func extractContextVars(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) map[string]string {
	vars := make(map[string]string)
	if req != nil {
		provider, model, _ := req.GetRequestFields()
		vars["provider"] = string(provider)
		vars["model"] = model
	}
	if ctx != nil {
		if vk := bifrostGetString(ctx, schemas.BifrostContextKeyVirtualKey); vk != "" {
			vars["virtual_key"] = vk
		}
		if cust := bifrostGetString(ctx, schemas.BifrostContextKeyGovernanceCustomerName); cust != "" {
			vars["customer"] = cust
		} else if custID := bifrostGetString(ctx, schemas.BifrostContextKeyGovernanceCustomerID); custID != "" {
			vars["customer"] = custID
		}
		if team := bifrostGetString(ctx, schemas.BifrostContextKeyGovernanceTeamName); team != "" {
			vars["team"] = team
		} else if teamID := bifrostGetString(ctx, schemas.BifrostContextKeyGovernanceTeamID); teamID != "" {
			vars["team"] = teamID
		}
		if user := bifrostGetString(ctx, schemas.BifrostContextKeyUserName); user != "" {
			vars["user"] = user
		} else if userID := bifrostGetString(ctx, schemas.BifrostContextKeyUserID); userID != "" {
			vars["user"] = userID
		}
	}
	return vars
}

func bifrostGetString(ctx *schemas.BifrostContext, key schemas.BifrostContextKey) string {
	if ctx == nil {
		return ""
	}
	val := ctx.Value(key)
	if val == nil {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", val)
}
