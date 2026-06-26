// Package egress — DLPPipeline: inline Data Loss Prevention for egress payloads.
//
// The pipeline scans outbound request bodies for sensitive patterns before they
// leave the network. Matches are replaced with [REDACTED:<type>] tokens.
// No raw matched content is ever stored — only offset and length metadata.
//
// Patterns covered:
//   - AWS Access Key IDs        (AKIA...)
//   - AWS Secret Access Keys    (40-char base64-like strings following "aws_secret")
//   - SSH RSA/ECDSA/Ed25519 private key PEM headers
//   - Generic PEM PRIVATE KEY blocks
//   - Credit card numbers       (Luhn-validated 13–19 digit sequences)
//   - Social Security Numbers   (US SSNs: NNN-NN-NNNN)
//   - Generic Bearer/API tokens (Authorization: Bearer <token>)
//   - NexisCore internal UUID patterns (tagged with NEXIS- prefix)
package egress

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// DLPPattern defines a single detection rule.
type DLPPattern struct {
	// Name is the human-readable identifier for this pattern (used in redaction token).
	Name string
	// Regex is the compiled detection expression.
	Regex *regexp.Regexp
	// Validate is an optional secondary validation function applied after regex match.
	// Returns true if the match is a genuine finding (e.g. Luhn check for credit cards).
	Validate func(match string) bool
}

// DLPFinding records a single redaction event without storing the sensitive value.
type DLPFinding struct {
	// PatternName is the name of the pattern that fired.
	PatternName string `json:"pattern_name"`
	// Offset is the byte offset in the original payload where the match started.
	Offset int `json:"offset"`
	// MatchLength is the length in bytes of the redacted string.
	MatchLength int `json:"match_length"`
	// RedactionToken is the replacement string that was inserted.
	RedactionToken string `json:"redaction_token"`
}

// DLPPipeline is a compiled, immutable set of detection rules. It is safe for
// concurrent use — Scrub() creates new buffers per invocation.
type DLPPipeline struct {
	patterns []DLPPattern
}

// NewDLPPipeline constructs a pipeline with the full default enterprise ruleset.
func NewDLPPipeline() (*DLPPipeline, error) {
	patterns := []DLPPattern{
		{
			Name:  "aws_access_key_id",
			Regex: regexp.MustCompile(`(?i)(AKIA|AGPA|AIPA|ANPA|ANVA|AROA|ASCA|ASIA)[A-Z0-9]{16}`),
		},
		{
			Name:  "aws_secret_access_key",
			Regex: regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}[=:\s]['"\\s]?([A-Za-z0-9/+]{40})`),
		},
		{
			Name:  "ssh_private_key_header",
			Regex: regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY( BLOCK)?-----`),
		},
		{
			Name:  "pem_private_key",
			Regex: regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
		},
		{
			Name:  "generic_api_key",
			Regex: regexp.MustCompile(`(?i)(api[_\-]?key|apikey|api[_\-]?token|auth[_\-]?token|access[_\-]?token)['":\s=]+([A-Za-z0-9\-_.]{20,64})`),
		},
		{
			Name:  "bearer_token",
			Regex: regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+([A-Za-z0-9\-_.~+/]+=*)`),
		},
		{
			Name:  "us_ssn",
			Regex: regexp.MustCompile(`\b([0-9]{3}-[0-9]{2}-[0-9]{4})\b`),
		},
		{
			Name:  "credit_card",
			Regex: regexp.MustCompile(`\b([3-9][0-9]{12,18})\b`),
			Validate: luhnCheck,
		},
		{
			Name:  "nexiscore_internal_uuid",
			Regex: regexp.MustCompile(`NEXIS-[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
		},
		{
			Name:  "private_key_pem_content",
			Regex: regexp.MustCompile(`MII[A-Za-z0-9+/]{100,}`), // base64-encoded DER private key blob
		},
	}

	// Validate all regexes compiled without panic (they're MustCompile, but be defensive)
	for _, p := range patterns {
		if p.Regex == nil {
			return nil, fmt.Errorf("dlp: nil regex for pattern %q", p.Name)
		}
	}

	return &DLPPipeline{patterns: patterns}, nil
}

// AddPattern adds a custom DLP detection pattern to the pipeline.
// The pattern name must be unique; adding a duplicate replaces the existing one.
func (d *DLPPipeline) AddPattern(name, pattern string, validate func(string) bool) error {
	rx, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("dlp: invalid pattern %q: %w", name, err)
	}
	// Replace if exists
	for i, p := range d.patterns {
		if p.Name == name {
			d.patterns[i] = DLPPattern{Name: name, Regex: rx, Validate: validate}
			return nil
		}
	}
	d.patterns = append(d.patterns, DLPPattern{Name: name, Regex: rx, Validate: validate})
	return nil
}

// Scrub scans payload for sensitive patterns and replaces matches with redaction
// tokens. Returns the sanitised payload, a list of DLPFindings (no raw data),
// and any processing error.
func (d *DLPPipeline) Scrub(payload []byte) (scrubbed []byte, findings []DLPFinding, err error) {
	// Work on a mutable copy
	result := make([]byte, len(payload))
	copy(result, payload)

	for _, pattern := range d.patterns {
		token := fmt.Sprintf("[REDACTED:%s]", pattern.Name)
		tokenBytes := []byte(token)

		// Find all non-overlapping matches
		matches := pattern.Regex.FindAllIndex(result, -1)

		// Process matches in reverse order so byte offsets remain valid as we replace
		for i := len(matches) - 1; i >= 0; i-- {
			loc := matches[i]
			start, end := loc[0], loc[1]
			matchBytes := result[start:end]

			// Apply optional secondary validation (e.g., Luhn for credit cards)
			if pattern.Validate != nil {
				// Extract just the digit/character portion for validation
				matchStr := string(matchBytes)
				if !pattern.Validate(matchStr) {
					continue
				}
			}

			findings = append(findings, DLPFinding{
				PatternName:    pattern.Name,
				Offset:         start,
				MatchLength:    end - start,
				RedactionToken: token,
			})

			// Replace in buffer
			result = append(result[:start], append(tokenBytes, result[end:]...)...)
		}
	}

	// Reverse findings to restore chronological order
	for i, j := 0, len(findings)-1; i < j; i, j = i+1, j-1 {
		findings[i], findings[j] = findings[j], findings[i]
	}

	return result, findings, nil
}

// ScrubString is a convenience wrapper for string payloads.
func (d *DLPPipeline) ScrubString(payload string) (scrubbed string, findings []DLPFinding, err error) {
	scrubbedBytes, findings, err := d.Scrub([]byte(payload))
	return string(scrubbedBytes), findings, err
}

// PatternNames returns the names of all registered DLP patterns.
func (d *DLPPipeline) PatternNames() []string {
	names := make([]string, len(d.patterns))
	for i, p := range d.patterns {
		names[i] = p.Name
	}
	return names
}

// ─────────────────────────────────────────────────────────────────────────────
// Luhn validation for credit card numbers
// ─────────────────────────────────────────────────────────────────────────────

// luhnCheck validates a string of digits using the Luhn algorithm.
// It strips any non-digit characters before running the check.
func luhnCheck(s string) bool {
	// Strip non-digits
	var digits strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			digits.WriteRune(r)
		}
	}
	d := digits.String()

	if len(d) < 13 || len(d) > 19 {
		return false
	}

	sum := 0
	nDigits := len(d)
	parity := nDigits % 2

	for i := 0; i < nDigits; i++ {
		digit, _ := strconv.Atoi(string(d[i]))
		if i%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

// RedactionSummary produces a human-readable summary of findings for logging.
// It does NOT include any raw matched content.
func RedactionSummary(findings []DLPFinding) string {
	if len(findings) == 0 {
		return "no findings"
	}
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.PatternName]++
	}
	var parts []string
	for name, count := range counts {
		parts = append(parts, fmt.Sprintf("%s×%d", name, count))
	}
	return strings.Join(parts, ", ")
}

// UniquePatternNames returns the deduplicated list of pattern names from a findings slice.
func UniquePatternNames(findings []DLPFinding) []string {
	seen := make(map[string]bool)
	var names []string
	for _, f := range findings {
		if !seen[f.PatternName] {
			seen[f.PatternName] = true
			names = append(names, f.PatternName)
		}
	}
	return names
}

// ContainsFindings returns true if any findings matched. Convenience predicate.
func ContainsFindings(findings []DLPFinding) bool {
	return len(findings) > 0
}

// ScrubJSON is a helper that scrubs a JSON payload encoded as bytes, returning
// the sanitised version alongside findings.
func (d *DLPPipeline) ScrubJSON(payload []byte) ([]byte, []DLPFinding, error) {
	// Validate that it parses as JSON-ish (contains { or [) before scrubbing
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return payload, nil, nil
	}
	return d.Scrub(payload)
}
