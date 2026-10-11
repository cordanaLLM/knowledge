package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const canonicalJSONProfile = "go_indented_utf8_htmlsafe_newline"

type canonicalJSONRawVector struct {
	ID        string `json:"id"`
	RawUTF8   string `json:"raw_utf8"`
	RawBase64 string `json:"raw_base64"`
}

type canonicalJSONValueVector struct {
	ID        string            `json:"id"`
	Value     any               `json:"value"`
	Canonical map[string]string `json:"canonical"`
}

type canonicalJSONDepthVector struct {
	ID       string            `json:"id"`
	Levels   int               `json:"levels"`
	Expected map[string]string `json:"expected"`
}

type canonicalJSONVectors struct {
	SchemaVersion string `json:"schema_version"`
	Profiles      map[string]struct {
		Implementations []string `json:"implementations"`
	} `json:"profiles"`
	Values             []canonicalJSONValueVector `json:"values"`
	RejectRaw          []canonicalJSONRawVector   `json:"reject_raw"`
	RejectNoncanonical []canonicalJSONRawVector   `json:"reject_noncanonical"`
	Bounds             struct {
		ByteLimit struct {
			Maximum int64  `json:"maximum"`
			RawUTF8 string `json:"raw_utf8"`
		} `json:"byte_limit"`
		NestedArrays []canonicalJSONDepthVector `json:"nested_arrays"`
	} `json:"bounds"`
}

func loadCanonicalJSONVectors(t *testing.T, implementation string) canonicalJSONVectors {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "canonical-json", "v1", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors canonicalJSONVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.SchemaVersion != "1.0.0" {
		t.Fatalf("unsupported canonical JSON vector schema %q", vectors.SchemaVersion)
	}
	for _, candidate := range vectors.Profiles[canonicalJSONProfile].Implementations {
		if candidate == implementation {
			return vectors
		}
	}
	t.Fatalf("shared profile does not name %s", implementation)
	return canonicalJSONVectors{}
}

func canonicalJSONRawBytes(t *testing.T, vector canonicalJSONRawVector) []byte {
	t.Helper()
	if vector.RawUTF8 != "" {
		return []byte(vector.RawUTF8)
	}
	raw, err := base64.StdEncoding.DecodeString(vector.RawBase64)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSharedCanonicalJSONConformance(t *testing.T) {
	vectors := loadCanonicalJSONVectors(t, "tools/knowledge-retrieval/util.go")
	for _, vector := range vectors.Values {
		t.Run("value/"+vector.ID, func(t *testing.T) {
			actual, err := marshalDocument(vector.Value)
			if err != nil {
				t.Fatal(err)
			}
			if expected := []byte(vector.Canonical[canonicalJSONProfile]); !bytes.Equal(actual, expected) {
				t.Fatalf("canonical bytes differ\ngot:  %q\nwant: %q", actual, expected)
			}
			var decoded any
			if err := decodeStrictCanonical(actual, &decoded); err != nil {
				t.Fatalf("canonical vector rejected: %v", err)
			}
		})
	}
	for _, vector := range append(vectors.RejectRaw, vectors.RejectNoncanonical...) {
		t.Run("reject/"+vector.ID, func(t *testing.T) {
			var decoded any
			if err := decodeStrictCanonical(canonicalJSONRawBytes(t, vector), &decoded); err == nil {
				t.Fatal("invalid or noncanonical vector was accepted")
			}
		})
	}
	t.Run("byte-limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bounded.json")
		if err := os.WriteFile(path, []byte(vectors.Bounds.ByteLimit.RawUTF8), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readStableFile(path, "byte-limit", vectors.Bounds.ByteLimit.Maximum); err == nil {
			t.Fatal("oversized vector was accepted")
		}
	})
	for _, vector := range vectors.Bounds.NestedArrays {
		t.Run("depth/"+vector.ID, func(t *testing.T) {
			var value any = float64(0)
			for range vector.Levels {
				value = []any{value}
			}
			raw, err := marshalDocument(value)
			if err != nil {
				t.Fatal(err)
			}
			var decoded any
			err = decodeStrictCanonical(raw, &decoded)
			if vector.Expected[canonicalJSONProfile] == "accept" && err != nil {
				t.Fatalf("bounded vector rejected: %v", err)
			}
			if vector.Expected[canonicalJSONProfile] == "reject" && err == nil {
				t.Fatal("out-of-bound vector was accepted")
			}
		})
	}
}
