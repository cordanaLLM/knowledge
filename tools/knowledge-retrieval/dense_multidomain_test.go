package main

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sealMultidomainDense builds a synthetic but structurally valid dense artifact
// over a candidate's document set with a caller-chosen lineage set, so tests can
// probe the multi-authority binding without a live embedding endpoint.
func sealMultidomainDense(candidate CandidateManifest, index LexicalIndex, lineages []AuthorityLineageBinding) DenseVectorArtifact {
	documents := make([]DenseDocumentVector, 0, len(index.Documents))
	for _, document := range index.Documents {
		documents = append(documents, DenseDocumentVector{DocumentID: document.DocumentID, Values: []int16{denseQuantizationScale, 0}})
	}
	sort.Slice(documents, func(i, j int) bool { return documents[i].DocumentID < documents[j].DocumentID })
	core := DenseVectorArtifactCore{
		SchemaVersion: retrievalSchemaVersion, ArtifactKind: "external_dense_document_vectors",
		State: "candidate_input", AuthorityState: "untrusted_candidate_input",
		LexicalCandidateID: candidate.ManifestID, LexicalIndexID: candidate.LexicalIndexID,
		EvidenceManifestID: candidate.EvidenceManifestID, Lineages: lineages,
		ModelID: "model:test-embedding", ModelRevision: "revision:test-embedding-1",
		ModelArtifactSHA256: "sha256:" + strings.Repeat("1", 64), TokenizerID: "tokenizer:test",
		TokenizerSHA256: "sha256:" + strings.Repeat("2", 64), EmbeddingProfile: "test-asymmetric@1.0.0",
		DocumentInstruction: "none", VectorEncoding: denseVectorEncoding, Normalization: denseVectorNormalization,
		QuantizationScale: denseQuantizationScale, Dimension: 2, DocumentCount: len(documents), Documents: documents,
	}
	coreBytes, _ := json.Marshal(core)
	digest := digestBytes(coreBytes)
	return DenseVectorArtifact{ArtifactID: "dense-vector-artifact:" + digest, ArtifactPayloadSHA256: digest, DenseVectorArtifactCore: core}
}

// TestMultidomainDenseConsumePath proves the retrieval consume path accepts a
// shared multi-authority candidate/index and binds a dense artifact to its exact
// lineage set — and fails closed on any lineage divergence.
func TestMultidomainDenseConsumePath(t *testing.T) {
	root := t.TempDir()
	cilium, golang, kubernetes := threeAuthorityFixtures(t, root)
	verifier, verifierHash := writeSharedVerifier(t, root, cilium, golang, kubernetes)
	store := filepath.Join(root, "retrieval")
	built, err := Build(multiBuildConfig(root, store, verifier, verifierHash, cilium.lineageConfig(), golang.lineageConfig(), kubernetes.lineageConfig()))
	if err != nil {
		t.Fatal(err)
	}
	candidate := built.Manifest
	if candidate.ManifestKind != lexicalMultidomainCandidate {
		t.Fatalf("fixture is not multidomain: %s", candidate.ManifestKind)
	}
	index, err := readBoundLexicalIndex(store, candidate)
	if err != nil {
		t.Fatal(err)
	}

	if err := validateCandidate(candidate); err != nil {
		t.Fatalf("consume path rejected a valid multidomain candidate: %v", err)
	}
	if err := validateIndex(index, candidate); err != nil {
		t.Fatalf("consume path rejected a valid multidomain index: %v", err)
	}

	// A multidomain index whose per-authority lineage document counts no longer
	// sum to the index total must fail closed, even though the lineage set is
	// still identical between the index and the candidate (lineagesEqual holds).
	skewedLineages := append([]AuthorityLineageBinding(nil), candidate.Lineages...)
	skewedLineages[0].DocumentCount++
	skewedCandidate := candidate
	skewedCandidate.Lineages = skewedLineages
	skewedIndex := index
	skewedIndex.Lineages = skewedLineages
	skewedCoreBytes, err := json.Marshal(skewedIndex.LexicalIndexCore)
	if err != nil {
		t.Fatal(err)
	}
	skewedIndex.IndexPayloadSHA256 = digestBytes(skewedCoreBytes)
	skewedIndex.IndexID = "lexical-index:" + skewedIndex.IndexPayloadSHA256
	skewedCandidate.LexicalIndexID = skewedIndex.IndexID
	if err := validateIndex(skewedIndex, skewedCandidate); err == nil || !strings.Contains(err.Error(), "sum") {
		t.Fatalf("multidomain lineage document counts not summing to the index total were accepted: %v", err)
	}

	maxDocuments, maxDimension, err := normalizeDenseLimits(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDenseArtifact(sealMultidomainDense(candidate, index, candidate.Lineages), candidate, index, maxDocuments, maxDimension); err != nil {
		t.Fatalf("matching multidomain dense artifact rejected: %v", err)
	}

	// A dense artifact whose lineages diverge from the candidate must fail closed.
	tampered := append([]AuthorityLineageBinding(nil), candidate.Lineages...)
	tampered[0].DocumentCount++
	if err := validateDenseArtifact(sealMultidomainDense(candidate, index, tampered), candidate, index, maxDocuments, maxDimension); err == nil || !strings.Contains(err.Error(), "authority lineage mismatch") {
		t.Fatalf("tampered dense lineages accepted: %v", err)
	}
	// A dense artifact with no lineages cannot bind a multidomain candidate.
	if err := validateDenseArtifact(sealMultidomainDense(candidate, index, nil), candidate, index, maxDocuments, maxDimension); err == nil {
		t.Fatalf("dense artifact without lineages accepted for a multidomain candidate")
	}
}

func TestLineagesEqual(t *testing.T) {
	base := []AuthorityLineageBinding{{AuthorityID: "x", DocumentCount: 1}, {AuthorityID: "y", DocumentCount: 2}}
	clone := append([]AuthorityLineageBinding(nil), base...)
	if !lineagesEqual(base, clone) {
		t.Fatal("identical lineage sets reported unequal")
	}
	if lineagesEqual(base, base[:1]) {
		t.Fatal("different-length lineage sets reported equal")
	}
	changed := append([]AuthorityLineageBinding(nil), base...)
	changed[1].DocumentCount = 99
	if lineagesEqual(base, changed) {
		t.Fatal("content-different lineage sets reported equal")
	}
	if !lineagesEqual(nil, nil) {
		t.Fatal("nil lineage sets reported unequal")
	}
}

func TestValidateAuthorityLineages(t *testing.T) {
	lineage := func(id, fill string, count int) AuthorityLineageBinding {
		return AuthorityLineageBinding{
			AuthorityID: id, ComponentID: "component:" + id, ComponentVersion: "v" + id,
			AdmissionPolicyScopeID: "scope:" + id, SourceID: "src:" + id, SnapshotID: "snap:" + id,
			SnapshotManifestID: "s" + id, EvidenceManifestID: "e" + id, AdmissionPolicyID: "p" + id,
			SnapshotManifestDocumentSHA256: "sha256:" + strings.Repeat(fill, 64),
			EvidenceManifestDocumentSHA256: "sha256:" + strings.Repeat(fill, 64),
			AdmissionPolicyDocumentSHA256:  "sha256:" + strings.Repeat(fill, 64),
			AdmissionEvaluatedAt:           "2026-07-18T00:00:00Z", AdmissionFreshUntil: "2026-08-18T00:00:00Z",
			FreshnessState: "fresh", DocumentCount: count,
		}
	}
	good := []AuthorityLineageBinding{lineage("a", "1", 1), lineage("b", "2", 2)}
	if err := validateAuthorityLineages(good); err != nil {
		t.Fatalf("well-formed lineages rejected: %v", err)
	}
	if err := validateAuthorityLineages(nil); err == nil {
		t.Fatal("empty lineage set accepted")
	}
	if err := validateAuthorityLineages([]AuthorityLineageBinding{good[1], good[0]}); err == nil || !strings.Contains(err.Error(), "order") {
		t.Fatal("unsorted lineages accepted")
	}
	badDigest := append([]AuthorityLineageBinding(nil), good...)
	badDigest[0].EvidenceManifestDocumentSHA256 = "not-a-sha256"
	if err := validateAuthorityLineages(badDigest); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("malformed digest accepted: %v", err)
	}
	zeroCount := append([]AuthorityLineageBinding(nil), good...)
	zeroCount[0].DocumentCount = 0
	if err := validateAuthorityLineages(zeroCount); err == nil {
		t.Fatal("zero document count accepted")
	}
	badTime := append([]AuthorityLineageBinding(nil), good...)
	badTime[0].AdmissionEvaluatedAt = "yesterday"
	if err := validateAuthorityLineages(badTime); err == nil || !strings.Contains(err.Error(), "admission evaluation time") {
		t.Fatalf("malformed admission timestamp accepted: %v", err)
	}
	emptyFresh := append([]AuthorityLineageBinding(nil), good...)
	emptyFresh[0].FreshnessState = ""
	if err := validateAuthorityLineages(emptyFresh); err == nil || !strings.Contains(err.Error(), "provenance") {
		t.Fatalf("empty freshness state accepted: %v", err)
	}
}
