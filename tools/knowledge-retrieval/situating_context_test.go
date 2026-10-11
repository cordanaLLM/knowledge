package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testDocumentID(seed byte) string {
	return "lexical-document:sha256:" + strings.Repeat(string(rune('a'+seed)), 64)
}

func testCandidateID() string {
	return "retrieval-candidate:sha256:" + strings.Repeat("9", 64)
}

func testCandidateHash() string {
	return "sha256:" + strings.Repeat("8", 64)
}

func testGeneratorDigest() string {
	return "sha256:" + strings.Repeat("7", 64)
}

func validSituatingCore() SituatingContextCore {
	return SituatingContextCore{
		SchemaVersion: retrievalSchemaVersion, ContextKind: situatingContextKind,
		State: "candidate_input", AuthorityState: "untrusted_candidate_input",
		LexicalCandidateID: testCandidateID(), LexicalCandidateSHA256: testCandidateHash(),
		GeneratorModel: "ollama:qwen3.6:27b", GeneratorModelDigest: testGeneratorDigest(),
		GeneratorTemperature: 0, DocumentCount: 2,
		Documents: []SituatingContextDocument{
			{DocumentID: testDocumentID(0), Blurb: "First document blurb."},
			{DocumentID: testDocumentID(1), Blurb: "Second document blurb."},
		},
	}
}

func writeSituatingCore(t *testing.T, core SituatingContextCore) (string, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "core.json")
	data, err := marshalDocument(core)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, digestBytes(data)
}

// TestMaterializeSituatingContextRoundTrip proves a valid caller-authored core
// derives a stable content-addressed manifest that re-validates and is
// consumable by resolveSituatingBlurbs for its exact matching document set.
func TestMaterializeSituatingContextRoundTrip(t *testing.T) {
	corePath, _ := writeSituatingCore(t, validSituatingCore())
	store := t.TempDir()
	manifest, path, err := MaterializeSituatingContext(corePath, store)
	if err != nil {
		t.Fatalf("materialize failed: %v", err)
	}
	if !strings.HasPrefix(manifest.ContextID, situatingContextIDPrefix) {
		t.Fatalf("unexpected context id: %s", manifest.ContextID)
	}
	if err := validateSituatingContext(manifest); err != nil {
		t.Fatalf("materialized manifest failed validation: %v", err)
	}
	// A second materialization from the identical core is byte-identical.
	second, _, err := MaterializeSituatingContext(corePath, store)
	if err != nil {
		t.Fatal(err)
	}
	if second.ContextID != manifest.ContextID {
		t.Fatalf("materialization is not deterministic: %s vs %s", manifest.ContextID, second.ContextID)
	}
	if path == "" {
		t.Fatal("expected a written path")
	}

	documents := []IndexedDocument{{DocumentID: testDocumentID(0)}, {DocumentID: testDocumentID(1)}}
	blurbs, err := resolveSituatingBlurbs(manifest, testCandidateID(), testCandidateHash(), documents)
	if err != nil {
		t.Fatalf("resolve blurbs on matching document set failed: %v", err)
	}
	if blurbs[testDocumentID(0)] != "First document blurb." {
		t.Fatalf("unexpected blurb text: %q", blurbs[testDocumentID(0)])
	}
}

// TestValidateSituatingContextFailsClosed proves every deliberate deviation
// from the fixed contract is rejected rather than silently accepted.
func TestValidateSituatingContextFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*SituatingContextCore)
	}{
		{"nonzero temperature", func(c *SituatingContextCore) { c.GeneratorTemperature = 0.2 }},
		{"empty blurb", func(c *SituatingContextCore) { c.Documents[0].Blurb = "" }},
		{"whitespace padded blurb", func(c *SituatingContextCore) { c.Documents[0].Blurb = " First document blurb. " }},
		{"oversized blurb", func(c *SituatingContextCore) { c.Documents[0].Blurb = strings.Repeat("x", maxSituatingBlurbBytes+1) }},
		{"unsorted documents", func(c *SituatingContextCore) {
			c.Documents[0], c.Documents[1] = c.Documents[1], c.Documents[0]
		}},
		{"duplicate document id", func(c *SituatingContextCore) {
			c.Documents[1].DocumentID = c.Documents[0].DocumentID
		}},
		{"document count mismatch", func(c *SituatingContextCore) { c.DocumentCount = 1 }},
		{"bad document id prefix", func(c *SituatingContextCore) {
			c.Documents[0].DocumentID = "evidence-span:sha256:" + strings.Repeat("a", 64)
		}},
		{"bad candidate id prefix", func(c *SituatingContextCore) {
			c.LexicalCandidateID = "hybrid-retrieval-candidate:sha256:" + strings.Repeat("9", 64)
		}},
		{"bad generator digest", func(c *SituatingContextCore) { c.GeneratorModelDigest = "not-a-digest" }},
		{"wrong schema version", func(c *SituatingContextCore) { c.SchemaVersion = "9.9.9" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core := validSituatingCore()
			tc.mutate(&core)
			// Compute the self-referential identity exactly like sealSituatingContext
			// (compact json.Marshal), so a rejected case fails on the mutated field,
			// not on an incidental identity mismatch from a different encoding.
			coreBytes, _ := json.Marshal(core)
			digest := digestBytes(coreBytes)
			manifest := SituatingContextManifest{ContextID: situatingContextIDPrefix + digest, ContextPayloadSHA256: digest, SituatingContextCore: core}
			if err := validateSituatingContext(manifest); err == nil {
				t.Fatalf("expected %s to fail closed", tc.name)
			}
		})
	}
}

// TestResolveSituatingBlurbsRequiresExactCoverage proves the 1:1 document<->blurb
// binding fails closed on any omission, orphan or wrong-candidate binding.
func TestResolveSituatingBlurbsRequiresExactCoverage(t *testing.T) {
	corePath, _ := writeSituatingCore(t, validSituatingCore())
	store := t.TempDir()
	manifest, _, err := MaterializeSituatingContext(corePath, store)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("missing blurb for a known document", func(t *testing.T) {
		documents := []IndexedDocument{{DocumentID: testDocumentID(0)}, {DocumentID: testDocumentID(1)}, {DocumentID: testDocumentID(2)}}
		if _, err := resolveSituatingBlurbs(manifest, testCandidateID(), testCandidateHash(), documents); err == nil {
			t.Fatal("expected missing-blurb document to fail closed")
		}
	})
	t.Run("orphaned blurb not in the document set", func(t *testing.T) {
		documents := []IndexedDocument{{DocumentID: testDocumentID(0)}}
		if _, err := resolveSituatingBlurbs(manifest, testCandidateID(), testCandidateHash(), documents); err == nil {
			t.Fatal("expected orphaned blurb to fail closed")
		}
	})
	t.Run("wrong candidate binding", func(t *testing.T) {
		documents := []IndexedDocument{{DocumentID: testDocumentID(0)}, {DocumentID: testDocumentID(1)}}
		if _, err := resolveSituatingBlurbs(manifest, "retrieval-candidate:sha256:"+strings.Repeat("1", 64), testCandidateHash(), documents); err == nil {
			t.Fatal("expected wrong candidate id to fail closed")
		}
		if _, err := resolveSituatingBlurbs(manifest, testCandidateID(), "sha256:"+strings.Repeat("1", 64), documents); err == nil {
			t.Fatal("expected wrong candidate hash to fail closed")
		}
	})
}

// TestSituateEmbeddingInput proves the historical no-blurb path is byte-for-byte
// unchanged and the blurb path deterministically prepends exactly one blurb.
func TestSituateEmbeddingInput(t *testing.T) {
	payload := []byte("exact normalized payload bytes")
	raw, err := situateEmbeddingInput(payload, nil, testDocumentID(0))
	if err != nil || raw != string(payload) {
		t.Fatalf("nil blurbs must reproduce the raw payload byte-for-byte: %q err=%v", raw, err)
	}
	blurbs := map[string]string{testDocumentID(0): "Situating blurb."}
	situated, err := situateEmbeddingInput(payload, blurbs, testDocumentID(0))
	if err != nil {
		t.Fatal(err)
	}
	want := "Situating blurb." + situatingBlurbSeparator + string(payload)
	if situated != want {
		t.Fatalf("situated input = %q, want %q", situated, want)
	}
	if _, err := situateEmbeddingInput(payload, blurbs, testDocumentID(1)); err == nil {
		t.Fatal("expected missing blurb for an unbound document id to fail closed")
	}
}
