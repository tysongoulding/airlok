package mock

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// GuardrailAction defines the intervention action.
type GuardrailAction string

const (
	ActionDetectOnly GuardrailAction = "detect_only"
	ActionBlock      GuardrailAction = "block"
	ActionRedact     GuardrailAction = "redact"
)

// RedactionStrategy defines how matched spans are transformed.
type RedactionStrategy string

const (
	StrategyReplace RedactionStrategy = "replace"
	StrategyMask    RedactionStrategy = "mask"
	StrategyHash    RedactionStrategy = "hash"
)

// RedactionMode defines where the redaction takes effect.
type RedactionMode string

const (
	RedactionModeRuntime           RedactionMode = "runtime"
	RedactionModeLogsOnly          RedactionMode = "logs_only"
	RedactionModeRuntimeReversible RedactionMode = "runtime_reversible"
)

// GuardrailFinding represents a detected entity.
type GuardrailFinding struct {
	RuleID      int               `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	EntityType  string            `json:"entity_type"`
	StartIndex  int               `json:"start_index"`
	EndIndex    int               `json:"end_index"`
	MatchedText string            `json:"matched_text"`
	Action      GuardrailAction   `json:"action"`
	Strategy    RedactionStrategy `json:"strategy,omitempty"`
}

// GuardrailEvaluationResult represents the outcome of evaluation.
type GuardrailEvaluationResult struct {
	Allowed            bool               `json:"allowed"`
	ActionTaken        GuardrailAction    `json:"action_taken"`
	Findings           []GuardrailFinding `json:"findings"`
	TransformedText    string             `json:"transformed_text,omitempty"`
	InterventionReason string             `json:"intervention_reason,omitempty"`
	EvaluationLatency  time.Duration      `json:"evaluation_latency"`
}

// GuardrailRule defines a configured rule.
type GuardrailRule struct {
	ID            int
	Name          string
	Enabled       bool
	Target        string // "llm", "mcp"
	CELExpression string
	ApplyTo       string // "input", "output", "both"
	Action        GuardrailAction
	Strategy      RedactionStrategy
	Mode          RedactionMode
	Patterns      []*regexp.Regexp
	EntityTypes   []string
}

// Built-in PII and Secrets Regexes.
var (
	RegexEmail      = regexp.MustCompile(`(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	RegexSSN        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	RegexCreditCard = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`)
	RegexPhone      = regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`)
	RegexIPv4       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	RegexAWSKey     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	RegexJWT        = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`)
	RegexPrivateKey = regexp.MustCompile(`-----BEGIN (?:RSA )?PRIVATE KEY-----`)
)

// MockGuardrailsEngine provides in-process, sub-millisecond guardrails evaluation.
type MockGuardrailsEngine struct {
	Rules              []GuardrailRule
	BedrockHookMock    func(text string) (bool, string, error)
	AzureHookMock      func(text string) (bool, []string, error)
	ModelArmorHookMock func(text string) (bool, string, error)
}

// NewMockGuardrailsEngine creates an engine initialized with standard enterprise rules.
func NewMockGuardrailsEngine() *MockGuardrailsEngine {
	engine := &MockGuardrailsEngine{
		Rules: []GuardrailRule{
			{
				ID:          101,
				Name:        "PII Protection - SSN & Credit Card Block",
				Enabled:     true,
				Target:      "llm",
				ApplyTo:     "both",
				Action:      ActionBlock,
				Patterns:    []*regexp.Regexp{RegexSSN, RegexCreditCard},
				EntityTypes: []string{"US_SSN", "CREDIT_CARD"},
			},
			{
				ID:          102,
				Name:        "PII Protection - Email & Phone Redaction",
				Enabled:     true,
				Target:      "llm",
				ApplyTo:     "both",
				Action:      ActionRedact,
				Strategy:    StrategyReplace,
				Mode:        RedactionModeRuntime,
				Patterns:    []*regexp.Regexp{RegexEmail, RegexPhone},
				EntityTypes: []string{"EMAIL", "PHONE"},
			},
			{
				ID:          103,
				Name:        "Secrets Leak Prevention",
				Enabled:     true,
				Target:      "both",
				ApplyTo:     "both",
				Action:      ActionBlock,
				Patterns:    []*regexp.Regexp{RegexAWSKey, RegexJWT, RegexPrivateKey},
				EntityTypes: []string{"AWS_KEY", "JWT_SECRET", "PRIVATE_KEY"},
			},
		},
	}
	return engine
}

// AddRule registers an additional custom rule.
func (e *MockGuardrailsEngine) AddRule(rule GuardrailRule) {
	e.Rules = append(e.Rules, rule)
}

// EvaluateText performs sub-millisecond regex scanning and redaction.
func (e *MockGuardrailsEngine) EvaluateText(text string, target string, phase string, metadata map[string]string) *GuardrailEvaluationResult {
	start := time.Now()
	res := &GuardrailEvaluationResult{
		Allowed:         true,
		ActionTaken:     ActionDetectOnly,
		Findings:        make([]GuardrailFinding, 0),
		TransformedText: text,
	}

	transformed := text

	for _, rule := range e.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.Target != "both" && rule.Target != target && target != "" {
			continue
		}
		if rule.ApplyTo != "both" && rule.ApplyTo != phase && phase != "" {
			continue
		}

		// Simple CEL expression simulation
		if rule.CELExpression != "" {
			if !e.evaluateCEL(rule.CELExpression, metadata) {
				continue
			}
		}

		for idx, pattern := range rule.Patterns {
			matches := pattern.FindAllStringIndex(text, -1)
			entityType := "CUSTOM"
			if idx < len(rule.EntityTypes) {
				entityType = rule.EntityTypes[idx]
			}

			for _, match := range matches {
				matchedText := text[match[0]:match[1]]
				finding := GuardrailFinding{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					EntityType:  entityType,
					StartIndex:  match[0],
					EndIndex:    match[1],
					MatchedText: matchedText,
					Action:      rule.Action,
					Strategy:    rule.Strategy,
				}
				res.Findings = append(res.Findings, finding)

				if rule.Action == ActionBlock {
					res.Allowed = false
					res.ActionTaken = ActionBlock
					res.InterventionReason = fmt.Sprintf("Guardrail violation: [%s] blocked the request due to %s", rule.Name, entityType)
				} else if rule.Action == ActionRedact && res.Allowed {
					res.ActionTaken = ActionRedact
					replacement := e.applyRedaction(matchedText, entityType, rule.Strategy)
					transformed = strings.ReplaceAll(transformed, matchedText, replacement)
				}
			}
		}
	}

	// External Hooks if configured
	if e.BedrockHookMock != nil && res.Allowed {
		allowed, reason, err := e.BedrockHookMock(text)
		if err == nil && !allowed {
			res.Allowed = false
			res.ActionTaken = ActionBlock
			res.InterventionReason = reason
		}
	}
	if e.AzureHookMock != nil && res.Allowed {
		allowed, categories, err := e.AzureHookMock(text)
		if err == nil && !allowed {
			res.Allowed = false
			res.ActionTaken = ActionBlock
			res.InterventionReason = fmt.Sprintf("Azure Content Safety violation: %s", strings.Join(categories, ", "))
		}
	}
	if e.ModelArmorHookMock != nil && res.Allowed {
		allowed, reason, err := e.ModelArmorHookMock(text)
		if err == nil && !allowed {
			res.Allowed = false
			res.ActionTaken = ActionBlock
			res.InterventionReason = reason
		}
	}

	res.TransformedText = transformed
	res.EvaluationLatency = time.Since(start)
	return res
}

func (e *MockGuardrailsEngine) applyRedaction(text string, entityType string, strategy RedactionStrategy) string {
	switch strategy {
	case StrategyMask:
		if len(text) <= 4 {
			return strings.Repeat("*", len(text))
		}
		return strings.Repeat("*", len(text)-4) + text[len(text)-4:]
	case StrategyHash:
		hash := sha256.Sum256([]byte(text))
		return hex.EncodeToString(hash[:8])
	case StrategyReplace:
		fallthrough
	default:
		return fmt.Sprintf("[%s]", entityType)
	}
}

func (e *MockGuardrailsEngine) evaluateCEL(expr string, metadata map[string]string) bool {
	// Evaluates expressions like: model == 'gpt-4o', provider == 'openai', headers['x-sensitive'] == 'true'
	if expr == "" || expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}
	if strings.Contains(expr, "==") {
		parts := strings.Split(expr, "==")
		key := strings.TrimSpace(parts[0])
		expected := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		actual, exists := metadata[key]
		if !exists {
			return false
		}
		return actual == expected
	}
	return true
}

// EvaluateStream simulates streaming output chunk accumulation and inspection.
func (e *MockGuardrailsEngine) EvaluateStream(chunks []string) (emitted []string, blocked bool, reason string) {
	var accumulator strings.Builder
	for _, chunk := range chunks {
		accumulator.WriteString(chunk)
		result := e.EvaluateText(accumulator.String(), "llm", "output", nil)
		if !result.Allowed {
			return nil, true, result.InterventionReason
		}
		emitted = append(emitted, chunk)
	}
	return emitted, false, ""
}
