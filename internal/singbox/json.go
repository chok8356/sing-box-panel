package singbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

// MaxJSONBytes limits every JSON document the panel stores.
const MaxJSONBytes = 2 << 20

// ValidateJSON accepts exactly one UTF-8 JSON value up to MaxJSONBytes.
func ValidateJSON(value string) error {
	if len(value) > MaxJSONBytes {
		return errors.New("JSON must be 2 MiB or smaller")
	}
	if !utf8.ValidString(value) || !json.Valid([]byte(value)) {
		return errors.New("enter valid UTF-8 JSON (one value, without comments or trailing commas)")
	}
	return nil
}

// FormatJSON re-indents value with two spaces, keeping numbers exact.
func FormatJSON(value string) (string, error) {
	if err := ValidateJSON(value); err != nil {
		return value, err
	}
	var out bytes.Buffer
	err := json.Indent(&out, []byte(value), "", "  ")
	return out.String(), err
}

// MergeJSON follows sing-box's merger: the first non-null scalar wins,
// objects combine recursively, and arrays concatenate in input order.
func MergeJSON(base, patch string) ([]byte, error) {
	target, err := decode(base)
	if err != nil {
		return nil, err
	}
	change, err := decode(patch)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(mergeValue(target, change), "", "  ")
}

func decode(value string) (any, error) {
	if err := ValidateJSON(value); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	decoder.UseNumber()
	var result any
	err := decoder.Decode(&result)
	return result, err
}

func mergeValue(target, patch any) any {
	if target == nil {
		return patch
	}
	if previous, ok := target.([]any); ok {
		if list, ok := patch.([]any); ok {
			return append(previous, list...)
		}
		return target
	}
	result, ok := target.(map[string]any)
	if !ok {
		return target
	}
	object, _ := patch.(map[string]any)
	for key, value := range object {
		result[key] = mergeValue(result[key], value)
	}
	return result
}
