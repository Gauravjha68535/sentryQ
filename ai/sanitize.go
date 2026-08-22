package ai

import (
	"strings"
	"unicode"
)

// SanitizePromptField removes known prompt injection vectors from untrusted
// metadata fields (issue names, file paths, descriptions, remediations) before
// they are embedded in any AI prompt.
//
// What it defends against:
//   - LLaMA ChatML special tokens (<|im_start|>, <|INST|>, etc.)
//   - XML/HTML tag breakout (</tag> escaping the wrapping delimiter)
//   - Unicode direction overrides (RLO/LRO that flip displayed vs. real content)
//   - Null bytes and other non-printable control characters that some models
//     treat as token boundaries or instruction delimiters
//   - Excessive newlines used to push injected instructions past the visible
//     context in reviewer UIs
//
// It does NOT defend against:
//   - Plain-English "ignore previous instructions" — that requires model-side
//     instruction following guarantees that no prompt sanitizer can provide.
//     The structural XML delimiters in the prompts (SECURITY NOTE) are the
//     primary defense for that class.
func SanitizePromptField(s string) string {
	if s == "" {
		return s
	}

	// Strip non-printable control characters (keeps \t and \n for readability)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\n' {
			b.WriteRune(' ') // normalise to space — don't preserve structure that could be exploited
			continue
		}
		if unicode.IsControl(r) {
			continue // drop null bytes, bells, backspaces, etc.
		}
		// Drop Unicode bidirectional overrides: RLO (U+202E), LRO (U+202D),
		// RLE (U+202B), LRE (U+202A), PDF (U+202C), FSI (U+2068), PDI (U+2069)
		if r == '‮' || r == '‭' || r == '‫' || r == '‪' ||
			r == '‬' || r == '⁨' || r == '⁩' {
			continue
		}
		b.WriteRune(r)
	}
	s = b.String()

	// LLaMA / Mistral ChatML special tokens
	s = strings.ReplaceAll(s, "<|", "< |")
	s = strings.ReplaceAll(s, "|>", "| >")

	// XML/HTML closing tag breakout — prevents </code_context> from escaping wrappers
	s = strings.ReplaceAll(s, "</", "<\\/")

	// Collapse runs of whitespace to prevent padding attacks that push injected
	// text below the context window of human reviewers
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}

	return strings.TrimSpace(s)
}

// SanitizeCodeContent escapes only the XML closing-tag breakout in raw source
// code. We cannot collapse whitespace or strip newlines in code — that would
// destroy indentation and line-number accuracy. We also cannot strip control
// chars since source files legitimately contain tabs.
func SanitizeCodeContent(s string) string {
	return strings.ReplaceAll(s, "</", "<\\/")
}
