package singbox

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestJSONFormattingPreservesNumbers(t *testing.T) {
	input := `{"n":900719925474099312345,"v":1.234567890123456789}`
	formatted, err := FormatJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	json.Unmarshal([]byte(input), &before)
	json.Unmarshal([]byte(formatted), &after)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("format changed JSON values")
	}
	if ValidateJSON(string([]byte{34, 255, 34})) == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestTailLogRetention(t *testing.T) {
	var logs TailLog
	logs.Write([]byte(strings.Repeat("a", MaxLogBytes*2) + "latest event"))
	if got := logs.String(); len(got) > MaxLogBytes || !strings.HasSuffix(got, "latest event") {
		t.Fatal("log retention failed")
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				logs.Write([]byte("event\n"))
				_ = logs.String()
			}
		}()
	}
	workers.Wait()
}

func normalizedJSON(t *testing.T, value []byte) string {
	t.Helper()
	var object any
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}
