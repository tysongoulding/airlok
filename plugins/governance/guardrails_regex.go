package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// RedactionAction defines whether to detect, block, or redact when a pattern matches.
type RedactionAction string

const (
	ActionDetectOnly RedactionAction = "detect_only"
	ActionBlock      RedactionAction = "block"
	ActionRedact     RedactionAction = "redact"
)

// RedactionStrategy defines how matched text is transformed.
type RedactionStrategy string

const (
	StrategyReplace RedactionStrategy = "replace"
	StrategyMask    RedactionStrategy = "mask"
	StrategyHash    RedactionStrategy = "hash"
)

// RedactionMode controls where redaction is applied (runtime, logs only, or reversible).
type RedactionMode string

const (
	ModeRuntime           RedactionMode = "runtime"
	ModeLogsOnly          RedactionMode = "logs_only"
	ModeRuntimeReversible RedactionMode = "runtime_reversible"
)

// RegexPatternConfig defines a configured regex pattern for guardrails inspection.
type RegexPatternConfig struct {
	ID          int               `json:"id"`
	Pattern     string            `json:"pattern"`
	Description string            `json:"description,omitempty"`
	EntityType  string            `json:"entity_type"`
	Flags       string            `json:"flags,omitempty"`
	Action      RedactionAction   `json:"action"`
	Strategy    RedactionStrategy `json:"strategy,omitempty"`
	Mode        RedactionMode     `json:"mode,omitempty"`
	Compiled    *regexp.Regexp    `json:"-"`
}

// CompileRegexWithFlags compiles an RE2 regex pattern prepending valid flags (i, m, s).
func CompileRegexWithFlags(pattern, flags string) (*regexp.Regexp, error) {
	cleanFlags := strings.ToLower(strings.TrimSpace(flags))
	var valid []rune
	for _, r := range cleanFlags {
		if r == 'i' || r == 'm' || r == 's' {
			valid = append(valid, r)
		}
	}
	prefix := ""
	if len(valid) > 0 {
		prefix = "(?" + string(valid) + ")"
	}
	return regexp.Compile(prefix + pattern)
}

// Pre-compiled built-in patterns for zero-latency execution.
var (
	regexEmail = regexp.MustCompile(`(?i)\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)
	regexPhone = regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`)
	regexSSN   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// Matches standard Visa, Mastercard, Amex, Discover and generic 13-19 digit credit card numbers
	regexCreditCard = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|(?:\d[ -]?){13,19})\b`)
	regexIPv4       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// Secrets detection patterns (Gitleaks rules)
	regexAWSKey     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	regexJWT        = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`)
	regexPrivateKey = regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----`)
	regexAPIKey     = regexp.MustCompile(`\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b`)
)

// BuiltinPIITemplates returns pre-compiled PII inspection patterns.
func BuiltinPIITemplates(defaultAction RedactionAction) []RegexPatternConfig {
	if defaultAction == "" {
		defaultAction = ActionRedact
	}
	return []RegexPatternConfig{
		{
			ID:          1,
			Pattern:     `(?i)\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`,
			Description: "Email address",
			EntityType:  "EMAIL",
			Action:      defaultAction,
			Strategy:    StrategyReplace,
			Mode:        ModeRuntime,
			Compiled:    regexEmail,
		},
		{
			ID:          2,
			Pattern:     `\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`,
			Description: "US phone number",
			EntityType:  "PHONE_NUMBER",
			Action:      defaultAction,
			Strategy:    StrategyReplace,
			Mode:        ModeRuntime,
			Compiled:    regexPhone,
		},
		{
			ID:          3,
			Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
			Description: "US Social Security Number",
			EntityType:  "US_SSN",
			Action:      ActionBlock, // SSN defaults to block
			Strategy:    StrategyReplace,
			Mode:        ModeRuntime,
			Compiled:    regexSSN,
		},
		{
			ID:          4,
			Pattern:     `\b(?:\d[ -]?){13,19}\b`,
			Description: "Credit card-like number",
			EntityType:  "CREDIT_CARD",
			Action:      ActionBlock, // Credit cards default to block
			Strategy:    StrategyReplace,
			Mode:        ModeRuntime,
			Compiled:    regexCreditCard,
		},
		{
			ID:          5,
			Pattern:     `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
			Description: "IPv4 address",
			EntityType:  "IP_ADDRESS",
			Action:      defaultAction,
			Strategy:    StrategyReplace,
			Mode:        ModeRuntime,
			Compiled:    regexIPv4,
		},
	}
}

// BuiltinSecretsTemplates returns pre-compiled secrets detection patterns.
func BuiltinSecretsTemplates() []RegexPatternConfig {
	return []RegexPatternConfig{
		{
			ID:          10,
			Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
			Description: "AWS Access Key",
			EntityType:  "AWS_KEY",
			Action:      ActionBlock,
			Strategy:    StrategyReplace,
			Mode:        ModeRuntime,
			Compiled:    regexAWSKey,
		},
		{
			ID:          11,
			Pattern:     `\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`,
			Description: "JSON Web Token (JWT)",
			EntityType:  "JWT",
			Action:      ActionBlock,
			Strategy:    StrategyReplace,
			Mode:        ModeRuntime,
			Compiled:    regexJWT,
		},
		{
			ID:          12,
			Pattern:     `-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----`,
			Description: "Private Key",
			EntityType:  "PRIVATE_KEY",
			Action:      ActionBlock,
			Strategy:    StrategyReplace,
			Mode:        ModeRuntime,
			Compiled:    regexPrivateKey,
		},
		{
			ID:          13,
			Pattern:     `\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b`,
			Description: "API Key / Token",
			EntityType:  "API_KEY",
			Action:      ActionBlock,
			Strategy:    StrategyReplace,
			Mode:        ModeRuntime,
			Compiled:    regexAPIKey,
		},
	}
}

// Span represents a detected entity interval in text.
type Span struct {
	Start       int               `json:"start"`
	End         int               `json:"end"`
	PatternID   int               `json:"pattern_id"`
	EntityType  string            `json:"entity_type"`
	Description string            `json:"description,omitempty"`
	MatchedText string            `json:"matched_text"`
	Action      RedactionAction   `json:"action"`
	Strategy    RedactionStrategy `json:"strategy,omitempty"`
	Mode        RedactionMode     `json:"mode,omitempty"`
}

// FindSpans scans text with compiled patterns and returns non-overlapping spans.
// Overlaps are resolved greedily: earlier start index wins, with longer match tie-breaker.
func FindSpans(patterns []RegexPatternConfig, text string) []Span {
	if len(patterns) == 0 || len(text) == 0 {
		return nil
	}

	var rawSpans []Span
	for _, p := range patterns {
		if p.Compiled == nil {
			continue
		}
		matches := p.Compiled.FindAllStringIndex(text, -1)
		for _, m := range matches {
			rawSpans = append(rawSpans, Span{
				Start:       m[0],
				End:         m[1],
				PatternID:   p.ID,
				EntityType:  p.EntityType,
				Description: p.Description,
				MatchedText: text[m[0]:m[1]],
				Action:      p.Action,
				Strategy:    p.Strategy,
				Mode:        p.Mode,
			})
		}
	}

	if len(rawSpans) <= 1 {
		return rawSpans
	}

	// Sort spans: Start ascending; on tie, End descending (longest match wins)
	sort.Slice(rawSpans, func(i, j int) bool {
		if rawSpans[i].Start == rawSpans[j].Start {
			return rawSpans[i].End > rawSpans[j].End
		}
		return rawSpans[i].Start < rawSpans[j].Start
	})

	// Greedy non-overlapping interval selection
	resolved := make([]Span, 0, len(rawSpans))
	lastEnd := 0
	for _, span := range rawSpans {
		if span.Start >= lastEnd {
			resolved = append(resolved, span)
			lastEnd = span.End
		}
	}
	return resolved
}

// ReversibleContext manages numbered tokens and reversible reveal mappings.
type ReversibleContext struct {
	mu         sync.Mutex
	counters   map[string]int    // EntityType -> count
	tokenToRaw map[string]string // "EMAIL-1" -> "alex@example.com"
	rawToToken map[string]string // "alex@example.com" -> "[EMAIL-1]"
}

// NewReversibleContext creates a new thread-safe reversible context.
func NewReversibleContext() *ReversibleContext {
	return &ReversibleContext{
		counters:   make(map[string]int),
		tokenToRaw: make(map[string]string),
		rawToToken: make(map[string]string),
	}
}

// GetOrCreateToken returns an existing or creates a new numbered placeholder.
func (rc *ReversibleContext) GetOrCreateToken(entityType, rawText string) string {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if tok, ok := rc.rawToToken[rawText]; ok {
		return tok
	}
	rc.counters[entityType]++
	count := rc.counters[entityType]
	tokenName := fmt.Sprintf("%s-%d", entityType, count)
	wrapped := fmt.Sprintf("[%s]", tokenName)
	rc.tokenToRaw[tokenName] = rawText
	rc.rawToToken[rawText] = wrapped
	return wrapped
}

// GetMapping returns a snapshot of tokenName -> rawText.
func (rc *ReversibleContext) GetMapping() map[string]string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	res := make(map[string]string, len(rc.tokenToRaw))
	for k, v := range rc.tokenToRaw {
		res[k] = v
	}
	return res
}

// GetReverseMapping returns a snapshot of rawText -> token.
func (rc *ReversibleContext) GetReverseMapping() map[string]string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	res := make(map[string]string, len(rc.rawToToken))
	for k, v := range rc.rawToToken {
		res[k] = v
	}
	return res
}

// FormatStrategyToken transforms a matched string based on the chosen strategy.
func FormatStrategyToken(entityType, matched string, strategy RedactionStrategy) string {
	switch strategy {
	case StrategyReplace:
		return "[" + entityType + "]"
	case StrategyMask:
		return "[" + entityType + ":" + strings.Repeat("*", len(matched)) + "]"
	case StrategyHash:
		sum := sha256.Sum256([]byte(matched))
		return "[" + entityType + ":" + hex.EncodeToString(sum[:8]) + "]"
	default:
		return "[" + entityType + "]"
	}
}

// RedactText rewrites text applying the appropriate strategy and mode.
// It returns the runtimeText (forwarded to provider/client), logText (for logging/audit),
// literalMap (original -> transformed), and reversibleMap (token -> original).
func RedactText(text string, spans []Span, revCtx *ReversibleContext) (string, string, map[string]string, map[string]string) {
	if len(spans) == 0 {
		return text, text, nil, nil
	}
	if revCtx == nil {
		revCtx = NewReversibleContext()
	}

	var runtimeSB strings.Builder
	var logSB strings.Builder
	runtimeSB.Grow(len(text))
	logSB.Grow(len(text))

	literalMap := make(map[string]string)
	reversibleMap := make(map[string]string)

	lastEnd := 0
	for _, s := range spans {
		// Append preceding unchanged text segment
		segment := text[lastEnd:s.Start]
		runtimeSB.WriteString(segment)
		logSB.WriteString(segment)

		strategy := s.Strategy
		if strategy == "" {
			strategy = StrategyReplace
		}
		mode := s.Mode
		if mode == "" {
			mode = ModeRuntime
		}

		switch mode {
		case ModeRuntime:
			token := FormatStrategyToken(s.EntityType, s.MatchedText, strategy)
			runtimeSB.WriteString(token)
			logSB.WriteString(token)
			literalMap[s.MatchedText] = token

		case ModeLogsOnly:
			// Runtime gets raw untouched text; log gets reversible placeholder
			runtimeSB.WriteString(s.MatchedText)
			revToken := revCtx.GetOrCreateToken(s.EntityType, s.MatchedText)
			logSB.WriteString(revToken)
			literalMap[s.MatchedText] = revToken
			reversibleMap[revToken] = s.MatchedText

		case ModeRuntimeReversible:
			// Both runtime and logs get reversible placeholder
			revToken := revCtx.GetOrCreateToken(s.EntityType, s.MatchedText)
			runtimeSB.WriteString(revToken)
			logSB.WriteString(revToken)
			literalMap[s.MatchedText] = revToken
			reversibleMap[revToken] = s.MatchedText
		}

		lastEnd = s.End
	}

	trailing := text[lastEnd:]
	runtimeSB.WriteString(trailing)
	logSB.WriteString(trailing)

	return runtimeSB.String(), logSB.String(), literalMap, reversibleMap
}
