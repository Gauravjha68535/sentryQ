package utils

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ExtractJSON attempts to find and return a valid JSON string from potentially noisy AI output.
// It handles <think> tags, markdown code blocks, and partial/truncated JSON.
func ExtractJSON(input string) string {
	// 1. Try to find content between ```json and ```
	reJSON := regexp.MustCompile("(?s)```[jJ][sS][oO][nN]\\s*(.*?)\\s*```")
	match := reJSON.FindStringSubmatch(input)
	if len(match) > 1 {
		return RepairJSON(strings.TrimSpace(match[1]))
	}

	// 2. Try to find content between generic ``` and ```
	// We take the LAST matching block since chain-of-thought might include markdown blocks.
	reGeneric := regexp.MustCompile("(?s)```\\s*(.*?)\\s*```")
	matches := reGeneric.FindAllStringSubmatch(input, -1)
	if len(matches) > 0 {
		return RepairJSON(strings.TrimSpace(matches[len(matches)-1][1]))
	}

	// 3. Fallback: Strip <think>/<thinking> blocks if they are properly closed
	reThink := regexp.MustCompile(`(?s)<think(?:ing)?>.*?</think(?:ing)?>`)
	input = reThink.ReplaceAllString(input, "")

	// 4. Sanitize invalid JSON escape sequences
	input = sanitizeJSONEscapes(input)

	// 5. Hard Fallback: Find the LAST starting { or [ that could contain the main JSON
	// Since chain-of-thought might contain stray { or [, we look for the main block.
	// A good heuristic is scanning from the end. But since JSON could be truncated,
	// let's find the FIRST { or [ AFTER any unclosed <thinking> tag.
	// Instead, just find the *last* occurrence of "vulnerabilities": [ or something?
	// No, let's just find the last `{` or `[` that spans to the end, but wait, 
	// what if we just find the first `{` or `[` of the remaining text?
	// If there's an unclosed <thinking> tag, the text might literally be:
	// <thinking>...
	// { "vulnerabilities": ...
	
	idxUnclosedThink := strings.LastIndex(input, "<think")
	searchFrom := 0
	if idxUnclosedThink != -1 && !strings.Contains(input[idxUnclosedThink:], "</think") {
		// Attempt to guess where thinking stops and JSON begins. 
		// Look for the first `{` or `[` after the last \n\n or \n{
		guessStart := strings.IndexAny(input[idxUnclosedThink:], "{[")
		if guessStart != -1 {
			searchFrom = idxUnclosedThink + guessStart
		}
	}

	startIdx := strings.IndexAny(input[searchFrom:], "{[")
	if startIdx >= 0 {
		startIdx += searchFrom
		var stack []rune
		var endIdx int = -1
		// Limit stack depth to prevent O(N) memory growth on pathologically
		// nested or malformed LLM output (e.g. millions of unclosed braces).
		const maxBracketDepth = 10000

		for i, r := range input[startIdx:] {
			if r == '{' {
				if len(stack) >= maxBracketDepth {
					break // treat as truncated
				}
				stack = append(stack, '}')
			} else if r == '[' {
				if len(stack) >= maxBracketDepth {
					break
				}
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
		// If never balanced, it's likely truncated JSON at the end
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

	// Pre-repair: strip trailing commas before } and ] (very common AI mistake)
	reTrailingComma := regexp.MustCompile(`,\s*([}\]])`)
	input = reTrailingComma.ReplaceAllString(input, "$1")

	// Use a stack to track open structures in order, and track if we are inside a string
	var stack []rune
	inString := false
	var escapeNext bool

	for _, r := range input {
		if escapeNext {
			escapeNext = false
			continue
		}

		if r == '\\' && inString {
			escapeNext = true
			continue
		}

		if r == '"' {
			inString = !inString
			continue
		}

		if !inString {
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
	}

	// Close open string if necessary
	if inString {
		input += `"`
	}

	// Remove trailing commas if we are about to close a structure
	if len(stack) > 0 {
		input = strings.TrimSpace(input)
		input = strings.TrimSuffix(input, ",")
	}

	// Close structures in reverse order of opening
	for i := len(stack) - 1; i >= 0; i-- {
		input += string(stack[i])
	}

	// Check validity again after repair. 
	// If it's still invalid, it might have been cut off in the middle of a key (e.g., `{"reas`).
	// We can't easily auto-fix half-keys perfectly, but adding `"}` will usually turn `{"reas` into `{"reas"}` !
	// Wait, we added `"` if `inString` was true. `{"reas` => inside string. It becomes `{"reas"` -> `{"reas"}`. 
	// But what if `{"verdict": "keep", ` 
	// `inString`=false, stack=`}`. Trailing comma removed -> `{"verdict": "keep"`. Then `}` appended -> `{"verdict": "keep"}`. Valid!

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

