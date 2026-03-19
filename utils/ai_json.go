package utils

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ExtractJSON attempts to find and return a valid JSON string from potentially noisy AI output.
// It handles <think> tags, markdown code blocks, and partial/truncated JSON.
func ExtractJSON(input string) string {
	// 1. Strip <think>/<thinking> blocks (used by DeepSeek, Qwen reasoning models)
	reThink := regexp.MustCompile(`(?s)<think(?:ing)?>.*?</think(?:ing)?>`)
	input = reThink.ReplaceAllString(input, "")

	// 2. Sanitize invalid JSON escape sequences (AI often outputs Python-style \')
	input = sanitizeJSONEscapes(input)

	// 2. Try to find content between ```json and ```
	reJSON := regexp.MustCompile("(?s)```json\\s*(.*?)\\s*```")
	match := reJSON.FindStringSubmatch(input)
	if len(match) > 1 {
		return RepairJSON(strings.TrimSpace(match[1]))
	}

	// 3. Try to find content between generic ``` and ```
	reGeneric := regexp.MustCompile("(?s)```\\s*(.*?)\\s*```")
	match = reGeneric.FindStringSubmatch(input)
	if len(match) > 1 {
		return RepairJSON(strings.TrimSpace(match[1]))
	}

	// 4. Fallback: Find the first { or [ and do a balanced walk
	startIdx := strings.IndexAny(input, "{[")
	if startIdx >= 0 {
		var stack []rune
		var endIdx int = -1
		
		for i, r := range input[startIdx:] {
			if r == '{' {
				stack = append(stack, '}')
			} else if r == '[' {
				stack = append(stack, ']')
			} else if r == '}' || r == ']' {
				if len(stack) > 0 && stack[len(stack)-1] == r {
					stack = stack[:len(stack)-1]
					if len(stack) == 0 {
						endIdx = startIdx + i + 1
						break
					}
				}
			}
		}
		
		if endIdx != -1 {
			return RepairJSON(input[startIdx:endIdx])
		}
		// If never balanced, it's likely truncated, send the rest to RepairJSON
		return RepairJSON(strings.TrimSpace(input[startIdx:]))
	}

	return strings.TrimSpace(input)
}

// RepairJSON attempts to fix common JSON issues like truncated responses or missing braces.
func RepairJSON(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// If it's already valid JSON, return as is
	if json.Valid([]byte(input)) {
		return input
	}

	// Use a stack to track open structures in order
	var stack []rune
	for _, r := range input {
		if r == '{' {
			stack = append(stack, '}')
		} else if r == '[' {
			stack = append(stack, ']')
		} else if r == '}' || r == ']' {
			if len(stack) > 0 && stack[len(stack)-1] == r {
				stack = stack[:len(stack)-1]
			}
		}
	}

	// Close structures in reverse order of opening
	for i := len(stack) - 1; i >= 0; i-- {
		// Before appending the first closer, check for trailing comma
		if i == len(stack)-1 {
			input = strings.TrimSpace(input)
			input = strings.TrimSuffix(input, ",")
		}
		input += string(stack[i])
	}

	// Check validity again after repair
	if json.Valid([]byte(input)) {
		return input
	}

	return input
}

// sanitizeJSONEscapes fixes invalid escape sequences produced by AI models.
// JSON only allows: \" \\ \/ \b \f \n \r \t \uXXXX
// AI models often produce Python-style \' which crashes Go's JSON parser.
//
// Strategy: protect valid \\ pairs with a placeholder, fix invalid escapes, restore.
func sanitizeJSONEscapes(input string) string {
	// Step 1: Protect valid \\ (escaped backslash) with a placeholder
	const placeholder = "\x00DBLBACK\x00"
	protected := strings.ReplaceAll(input, `\\`, placeholder)

	// Step 2: Now any remaining single \ followed by an invalid char is truly invalid
	// Valid JSON escapes after \: " \ / b f n r t u
	re := regexp.MustCompile(`\\([^"\\/bfnrtu])`)
	fixed := re.ReplaceAllString(protected, "$1")

	// Step 3: Restore the placeholder back to \\
	return strings.ReplaceAll(fixed, placeholder, `\\`)
}

// EscapeUnescapedQuotes repairs AI JSON where double quotes inside string values
// are not properly escaped. For example, PHP code like: echo "<h1>";\n
// The AI escapes some " but misses others, breaking JSON structure.
//
// Strategy: walk char-by-char, track if inside a JSON string. When we see " that
// ends a string, check if the following non-whitespace char is valid JSON structure
// (: , } ]). If not, this " is actually part of the string content — escape it.
func EscapeUnescapedQuotes(input string) string {
	runes := []rune(input)
	n := len(runes)
	var result []rune
	inString := false
	i := 0

	for i < n {
		ch := runes[i]

		if !inString {
			result = append(result, ch)
			if ch == '"' {
				inString = true
			}
			i++
			continue
		}

		// We are inside a JSON string
		if ch == '\\' {
			// Escaped character — copy both the backslash and next char
			result = append(result, ch)
			i++
			if i < n {
				result = append(result, runes[i])
				i++
			}
			continue
		}

		if ch == '"' {
			// This might be the end of the string, or an unescaped quote
			// Look ahead: skip whitespace, then check what follows
			j := i + 1
			for j < n && (runes[j] == ' ' || runes[j] == '\t' || runes[j] == '\n' || runes[j] == '\r') {
				j++
			}

			validEnd := false
			if j >= n {
				validEnd = true // end of input = valid end of string
			} else {
				next := runes[j]
				// Valid chars after closing a JSON string: , } ] :
				if next == ',' || next == '}' || next == ']' || next == ':' {
					validEnd = true
				}
			}

			if validEnd {
				// This is a real string-close quote
				result = append(result, ch)
				inString = false
			} else {
				// This " is inside the string but not escaped — escape it
				result = append(result, '\\', '"')
			}
			i++
			continue
		}

		// Regular character inside string
		result = append(result, ch)
		i++
	}

	return string(result)
}

