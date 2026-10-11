package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFineSpanExtensionAddsChildDocumentSmallToBig proves the small-to-big
// contract end-to-end at the build layer: a fine window nested inside the
// coarse chunk's own already-admitted bytes becomes a second, independently
// retrievable document, byte-reproducibly, without changing the coarse
// document's own identity or the evidence manifest's own aggregates.
func TestFineSpanExtensionAddsChildDocumentSmallToBig(t *testing.T) {
	data := []byte("alpha beta DNSPolicy gamma delta\n")
	fx := newTestFixture(t, data, "2026-07-17T00:00:00Z")

	baseline, err := Build(fx.buildConfig(filepath.Join(fx.root, "retrieval-baseline")))
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Manifest.DocumentCount != 1 {
		t.Fatalf("baseline document count = %d, want 1", baseline.Manifest.DocumentCount)
	}
	coarseSpanID := fx.evidence.Files[0].Spans[0].SpanID

	start := int64(bytes.Index(data, []byte("DNSPolicy")))
	end := start + int64(len("DNSPolicy"))
	payloadResult, err := MaterializeFineSpanPayload(fx.rawRoot, fx.snapshot.Files[0].SHA256, fx.snapshot.Files[0].Size, fx.evidenceRoot, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if payloadResult.PayloadSHA256 != digestBytes(data[start:end]) {
		t.Fatalf("fine span payload digest = %s, want %s", payloadResult.PayloadSHA256, digestBytes(data[start:end]))
	}

	extPath := filepath.Join(fx.root, "fine-span-extension.json")
	writeCanonical(t, extPath, FineSpanExtensionInput{
		SchemaVersion: retrievalSchemaVersion,
		Documents: []FineSpanExtensionDocument{{
			ParentSpanID: coarseSpanID, Kind: "fine_span_extension",
			HeadingBreadcrumb: []string{"DNSPolicy"}, RawByteStart: start, RawByteEnd: end,
		}},
	})

	config := fx.buildConfig(fx.outputRoot)
	config.FineSpanExtensionPath = extPath
	first, err := Build(config)
	if err != nil {
		t.Fatal(err)
	}
	if first.Manifest.DocumentCount != 2 {
		t.Fatalf("extended document count = %d, want 2", first.Manifest.DocumentCount)
	}
	index, err := readBoundLexicalIndex(fx.outputRoot, first.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var fine, coarse *IndexedDocument
	for i := range index.Documents {
		document := &index.Documents[i]
		if document.Evidence.SpanID == coarseSpanID {
			coarse = document
			continue
		}
		if document.Evidence.ParentSpanID == coarseSpanID {
			fine = document
		}
	}
	if coarse == nil || fine == nil {
		t.Fatalf("expected one coarse and one fine document, got %#v", index.Documents)
	}
	if coarse.Evidence.ParentSpanID != "" {
		t.Fatalf("coarse document unexpectedly carries a ParentSpanID: %#v", coarse.Evidence)
	}
	if fine.Evidence.SpanID == coarseSpanID || fine.Evidence.SpanID == "" {
		t.Fatalf("fine document did not get its own distinct SpanID: %#v", fine.Evidence)
	}
	if fine.Evidence.PayloadSHA256 != payloadResult.PayloadSHA256 || fine.Evidence.PayloadObjectPath != payloadResult.ObjectPath {
		t.Fatalf("fine document payload binding mismatch: %#v vs %#v", fine.Evidence, payloadResult)
	}
	if fine.Evidence.RawByteStart != start || fine.Evidence.RawByteEnd != end {
		t.Fatalf("fine document byte window = [%d,%d), want [%d,%d)", fine.Evidence.RawByteStart, fine.Evidence.RawByteEnd, start, end)
	}

	// Coarse document identity must be untouched by adding the extension.
	baselineIndex, err := readBoundLexicalIndex(filepath.Join(fx.root, "retrieval-baseline"), baseline.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if baselineIndex.Documents[0].DocumentID != coarse.DocumentID {
		t.Fatalf("adding a fine span extension changed the coarse document identity: %s vs %s", baselineIndex.Documents[0].DocumentID, coarse.DocumentID)
	}

	// Reproducibility: a second independent build over a fresh store is
	// byte-identical.
	freshRoot := filepath.Join(fx.root, "retrieval-fresh")
	second, err := Build(config)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(first.ManifestPath)
	secondBytes, _ := os.ReadFile(second.ManifestPath)
	if first.Manifest.ManifestID != second.Manifest.ManifestID || !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("immutable object reuse changed the extended deterministic candidate")
	}
	config.OutputStoreRoot = freshRoot
	third, err := Build(config)
	if err != nil {
		t.Fatal(err)
	}
	thirdBytes, _ := os.ReadFile(third.ManifestPath)
	if first.Manifest.ManifestID != third.Manifest.ManifestID || !bytes.Equal(firstBytes, thirdBytes) {
		t.Fatal("fresh store changed the extended deterministic candidate")
	}
}

func TestFineSpanExtensionFailsClosed(t *testing.T) {
	data := []byte("alpha beta DNSPolicy gamma delta\n")
	fx := newTestFixture(t, data, "2026-07-17T00:00:00Z")
	coarseSpanID := fx.evidence.Files[0].Spans[0].SpanID
	start := int64(bytes.Index(data, []byte("DNSPolicy")))
	end := start + int64(len("DNSPolicy"))

	writeExtension := func(t *testing.T, documents []FineSpanExtensionDocument) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "fine-span-extension.json")
		writeCanonical(t, path, FineSpanExtensionInput{SchemaVersion: retrievalSchemaVersion, Documents: documents})
		return path
	}

	t.Run("parent span missing", func(t *testing.T) {
		ext := writeExtension(t, []FineSpanExtensionDocument{{
			ParentSpanID: "evidence-span:sha256:" + strings.Repeat("0", 64), Kind: "fine_span_extension",
			RawByteStart: start, RawByteEnd: end,
		}})
		config := fx.buildConfig(filepath.Join(fx.root, "out-missing-parent"))
		config.FineSpanExtensionPath = ext
		requireBuildQuarantine(t, config, "fine_span_parent_missing")
	})

	t.Run("window escapes parent", func(t *testing.T) {
		ext := writeExtension(t, []FineSpanExtensionDocument{{
			ParentSpanID: coarseSpanID, Kind: "fine_span_extension",
			RawByteStart: 0, RawByteEnd: int64(len(data)) + 1,
		}})
		config := fx.buildConfig(filepath.Join(fx.root, "out-window-escape"))
		config.FineSpanExtensionPath = ext
		requireBuildQuarantine(t, config, "fine_span_window_invalid")
	})

	t.Run("payload not yet materialized", func(t *testing.T) {
		ext := writeExtension(t, []FineSpanExtensionDocument{{
			ParentSpanID: coarseSpanID, Kind: "fine_span_extension",
			RawByteStart: start, RawByteEnd: end,
		}})
		config := fx.buildConfig(filepath.Join(fx.root, "out-not-materialized"))
		config.FineSpanExtensionPath = ext
		requireBuildQuarantine(t, config, "fine_span_payload_not_materialized")
	})

	t.Run("loader rejects unordered documents", func(t *testing.T) {
		ext := writeExtension(t, []FineSpanExtensionDocument{
			{ParentSpanID: coarseSpanID, Kind: "fine_span_extension", RawByteStart: 10, RawByteEnd: 20},
			{ParentSpanID: coarseSpanID, Kind: "fine_span_extension", RawByteStart: 0, RawByteEnd: 5},
		})
		if _, err := loadFineSpanExtension(ext); err == nil || !strings.Contains(err.Error(), "strict order") {
			t.Fatalf("expected strict order error, got %v", err)
		}
	})

	t.Run("loader rejects the coarse chunk kind", func(t *testing.T) {
		ext := writeExtension(t, []FineSpanExtensionDocument{
			{ParentSpanID: coarseSpanID, Kind: "document_chunk", RawByteStart: start, RawByteEnd: end},
		})
		if _, err := loadFineSpanExtension(ext); err == nil || !strings.Contains(err.Error(), "distinct from the coarse chunk kind") {
			t.Fatalf("expected coarse-kind rejection, got %v", err)
		}
	})
}
