package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestHybridQuerySmallToBigResolvesToEnclosingCoarseChunk proves the
// small-to-big query-time contract: a fine-span extension document that wins
// the fused ranking is returned as its enclosing coarse chunk's own Evidence
// (same SpanID, full coarse byte window), and a coarse hit that also
// independently matches is de-duplicated against it rather than shown twice.
func TestHybridQuerySmallToBigResolvesToEnclosingCoarseChunk(t *testing.T) {
	first := []byte("alpha lexical\n")
	second := []byte("beta semantic\n")
	data := append(append([]byte(nil), first...), second...)
	base := newTestFixture(t, data, "2026-07-17T00:00:00Z")
	replaceFixtureSpans(t, base, [][]byte{first, second})

	coarseSpan := base.evidence.Files[0].Spans[1]
	needle := []byte("semantic")
	start := coarseSpan.RawByteStart + int64(bytes.Index(second, needle))
	end := start + int64(len(needle))
	if _, err := MaterializeFineSpanPayload(base.rawRoot, base.snapshot.Files[0].SHA256, base.snapshot.Files[0].Size, base.evidenceRoot, start, end); err != nil {
		t.Fatal(err)
	}
	extPath := filepath.Join(base.root, "fine-span-extension.json")
	writeCanonical(t, extPath, FineSpanExtensionInput{
		SchemaVersion: retrievalSchemaVersion,
		Documents: []FineSpanExtensionDocument{{
			ParentSpanID: coarseSpan.SpanID, Kind: "fine_span_extension",
			HeadingBreadcrumb: []string{"semantic"}, RawByteStart: start, RawByteEnd: end,
		}},
	})

	buildConfig := base.buildConfig(base.outputRoot)
	buildConfig.FineSpanExtensionPath = extPath
	lexical, err := Build(buildConfig)
	if err != nil {
		t.Fatal(err)
	}
	if lexical.Manifest.DocumentCount != 3 {
		t.Fatalf("document count = %d, want 3", lexical.Manifest.DocumentCount)
	}
	index, err := readBoundLexicalIndex(base.outputRoot, lexical.Manifest)
	if err != nil {
		t.Fatal(err)
	}

	fx := &hybridTestFixture{testFixture: base, lexical: lexical, index: index, densePath: filepath.Join(base.root, "dense.json")}
	documents := make([]DenseDocumentVector, 0, len(index.Documents))
	for _, document := range index.Documents {
		vector := []int16{denseQuantizationScale, 0}
		if document.Evidence.RawByteStart != 0 {
			vector = []int16{0, denseQuantizationScale}
		} else {
			fx.alphaDocID = document.DocumentID
		}
		documents = append(documents, DenseDocumentVector{DocumentID: document.DocumentID, Values: vector})
	}
	fx.dense = DenseVectorArtifact{DenseVectorArtifactCore: DenseVectorArtifactCore{
		SchemaVersion: retrievalSchemaVersion, ArtifactKind: "external_dense_document_vectors",
		State: "candidate_input", AuthorityState: "untrusted_candidate_input",
		LexicalCandidateID: lexical.Manifest.ManifestID, LexicalIndexID: lexical.Manifest.LexicalIndexID,
		EvidenceManifestID: lexical.Manifest.EvidenceManifestID, ModelID: "model:test-embedding",
		ModelRevision: "revision:test-embedding-1", ModelArtifactSHA256: "sha256:" + strings.Repeat("1", 64),
		TokenizerID: "tokenizer:test-embedding", TokenizerSHA256: "sha256:" + strings.Repeat("2", 64),
		EmbeddingProfile: "test-asymmetric-embedding@1.0.0", DocumentInstruction: "Represent this technical evidence span for retrieval.",
		VectorEncoding: denseVectorEncoding, Normalization: denseVectorNormalization, QuantizationScale: denseQuantizationScale,
		Dimension: 2, DocumentCount: len(documents), Documents: documents,
	}}
	fx.resealDense(t)
	hybrid, err := Hybridize(fx.hybridBuildConfig())
	if err != nil {
		t.Fatal(err)
	}
	fx.hybrid = hybrid

	signals, signalsPath, _ := fx.writeSignals(t, "semantic", []int16{0, denseQuantizationScale}, nil)
	disableReranking(&signals)
	signalsHash := writeResealedSignals(t, signalsPath, &signals)

	config := fx.hybridQueryConfig(signalsPath, signalsHash, "semantic")
	config.Limit = 3
	config.FusionWindow = 3
	config.RerankWindow = 0
	response, err := QueryHybrid(config)
	if err != nil {
		t.Fatal(err)
	}
	if response.ResultState != "ok" {
		t.Fatalf("query response = %#v", response)
	}
	if len(response.Results) != 2 {
		t.Fatalf("expected small-to-big dedup to collapse 3 matches into 2 hits, got %d: %#v", len(response.Results), response.Results)
	}
	var resolved *HybridQueryHit
	for i := range response.Results {
		if response.Results[i].Evidence.SpanID == coarseSpan.SpanID {
			resolved = &response.Results[i]
		}
	}
	if resolved == nil {
		t.Fatalf("no hit resolved to the enclosing coarse chunk: %#v", response.Results)
	}
	if resolved.Evidence.RawByteStart != coarseSpan.RawByteStart || resolved.Evidence.RawByteEnd != coarseSpan.RawByteEnd {
		t.Fatalf("small-to-big hit did not return the full enclosing coarse window: %#v", resolved.Evidence)
	}
	if !strings.Contains(resolved.Excerpt, "beta semantic") {
		t.Fatalf("small-to-big hit excerpt is not the coarse chunk text: %q", resolved.Excerpt)
	}
}
