package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	situatingContextKind     = "index_time_situating_blurb_context"
	maxSituatingContextBytes = int64(8 * 1024 * 1024)
	maxSituatingBlurbBytes   = 2048
	minSituatingBlurbBytes   = 1
	situatingBlurbSeparator  = "\n\n"
	situatingContextIDPrefix = "situating-context:"
)

// SituatingContextDocument binds one committed index-time blurb to the exact
// lexical document it situates. The blurb is caller-authored (generated
// offline by a pinned local model at temperature 0) and committed as a fixed
// input; this tool never calls a generation model itself.
type SituatingContextDocument struct {
	DocumentID string `json:"document_id"`
	Blurb      string `json:"blurb"`
}

// SituatingContextCore is a caller-authored, immutable Contextual Retrieval
// input: a short situating blurb per lexical document, prepended to that
// document's exact normalized payload before embedding (Anthropic's
// "Contextual Retrieval" pattern, reproduced as a corpus-specific
// experiment). It carries no admission, quality or promotion authority — it
// only changes the untrusted dense artifact's embedding input, exactly like
// the existing per-artifact document_instruction flag, but per document
// instead of uniform. Binding it to one exact lexical candidate prevents one
// authority's blurbs from silently attaching to another candidate.
type SituatingContextCore struct {
	SchemaVersion          string                     `json:"schema_version"`
	ContextKind            string                     `json:"context_kind"`
	State                  string                     `json:"state"`
	AuthorityState         string                     `json:"authority_state"`
	LexicalCandidateID     string                     `json:"lexical_candidate_id"`
	LexicalCandidateSHA256 string                     `json:"lexical_candidate_document_sha256"`
	GeneratorModel         string                     `json:"generator_model"`
	GeneratorModelDigest   string                     `json:"generator_model_digest"`
	GeneratorTemperature   float64                    `json:"generator_temperature"`
	DocumentCount          int                        `json:"document_count"`
	Documents              []SituatingContextDocument `json:"documents"`
}

type SituatingContextManifest struct {
	ContextID            string `json:"context_id"`
	ContextPayloadSHA256 string `json:"context_payload_sha256"`
	SituatingContextCore
}

// MaterializeSituatingContext derives the immutable content-addressed identity
// of a caller-authored SituatingContextCore and commits it, mirroring
// MaterializeFusionProfile. It grants no source, quality or promotion
// authority — only a stable, tamper-evident identity for the committed blurbs.
func MaterializeSituatingContext(corePath, storeRoot string) (SituatingContextManifest, string, error) {
	var zero SituatingContextManifest
	if strings.TrimSpace(corePath) == "" || strings.TrimSpace(storeRoot) == "" {
		return zero, "", errors.New("situating context core path and store are required")
	}
	coreBytes, err := readStableFile(corePath, "situating context core", maxSituatingContextBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read situating context core: %w", err)
	}
	var core SituatingContextCore
	if err := decodeStrictCanonical(coreBytes, &core); err != nil {
		return zero, "", fmt.Errorf("decode situating context core: %w", err)
	}
	manifest, err := sealSituatingContext(core)
	if err != nil {
		return zero, "", err
	}
	data, err := marshalDocument(manifest)
	if err != nil {
		return zero, "", err
	}
	relative, err := contentObjectPath("situating-context", manifest.ContextPayloadSHA256)
	if err != nil {
		return zero, "", err
	}
	root, err := filepath.Abs(storeRoot)
	if err != nil || validateNoSymlinkExistingPrefix(root) != nil {
		return zero, "", errors.New("situating context store is unavailable")
	}
	if err := writeImmutableObject(root, relative, data); err != nil {
		return zero, "", fmt.Errorf("commit situating context: %w", err)
	}
	return manifest, filepath.Join(root, filepath.FromSlash(relative)), nil
}

func sealSituatingContext(core SituatingContextCore) (SituatingContextManifest, error) {
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return SituatingContextManifest{}, err
	}
	digest := digestBytes(coreBytes)
	manifest := SituatingContextManifest{
		ContextID:            situatingContextIDPrefix + digest,
		ContextPayloadSHA256: digest,
		SituatingContextCore: core,
	}
	if err := validateSituatingContext(manifest); err != nil {
		return SituatingContextManifest{}, fmt.Errorf("situating context core is invalid: %w", err)
	}
	return manifest, nil
}

// validateSituatingContext enforces the fail-closed shape independent of which
// lexical candidate it is later bound to: self-referential identity, a fixed
// deterministic (temperature 0) pinned local generator, and one bounded,
// non-empty blurb per document in strict ascending, unique DocumentID order.
func validateSituatingContext(manifest SituatingContextManifest) error {
	coreBytes, err := json.Marshal(manifest.SituatingContextCore)
	if err != nil || manifest.ContextPayloadSHA256 != digestBytes(coreBytes) || manifest.ContextID != situatingContextIDPrefix+manifest.ContextPayloadSHA256 {
		return errors.New("situating context identity mismatch")
	}
	if manifest.SchemaVersion != retrievalSchemaVersion || manifest.ContextKind != situatingContextKind || manifest.State != "candidate_input" || manifest.AuthorityState != "untrusted_candidate_input" {
		return errors.New("situating context envelope unsupported")
	}
	if !validPrefixedDigest(manifest.LexicalCandidateID, "retrieval-candidate:") || !validSHA256(manifest.LexicalCandidateSHA256) {
		return errors.New("situating context lexical candidate binding invalid")
	}
	if !boundedMetadata(manifest.GeneratorModel) || !validSHA256(manifest.GeneratorModelDigest) {
		return errors.New("situating context generator identity invalid")
	}
	if manifest.GeneratorTemperature != 0 {
		return errors.New("situating context generator must be deterministic (temperature 0)")
	}
	if manifest.DocumentCount != len(manifest.Documents) || manifest.DocumentCount < 1 {
		return errors.New("situating context document count invalid")
	}
	previous := ""
	for position, document := range manifest.Documents {
		if !validPrefixedDigest(document.DocumentID, "lexical-document:") {
			return errors.New("situating context document id invalid")
		}
		if position > 0 && document.DocumentID <= previous {
			return errors.New("situating context documents are not in strict document-ID order")
		}
		previous = document.DocumentID
		if err := validateSituatingBlurb(document.Blurb); err != nil {
			return err
		}
	}
	return nil
}

func validateSituatingBlurb(blurb string) error {
	trimmed := strings.TrimSpace(blurb)
	if trimmed != blurb {
		return errors.New("situating blurb carries leading or trailing whitespace")
	}
	size := len(blurb)
	if size < minSituatingBlurbBytes || size > maxSituatingBlurbBytes {
		return errors.New("situating blurb is outside the bounded length")
	}
	return nil
}

// resolveSituatingBlurbs requires the manifest to bind exactly the given
// lexical candidate and to carry exactly one blurb per document in the
// caller's document set — no omissions, no orphans. It fails closed rather
// than silently leaving any document unsituated or any blurb unused.
func resolveSituatingBlurbs(manifest SituatingContextManifest, candidateID, candidateHash string, documents []IndexedDocument) (map[string]string, error) {
	if err := validateSituatingContext(manifest); err != nil {
		return nil, fmt.Errorf("situating context is invalid: %w", err)
	}
	if manifest.LexicalCandidateID != candidateID || manifest.LexicalCandidateSHA256 != candidateHash {
		return nil, errors.New("situating context is not bound to this exact lexical candidate")
	}
	expected := make(map[string]struct{}, len(documents))
	for _, document := range documents {
		expected[document.DocumentID] = struct{}{}
	}
	blurbs := make(map[string]string, len(manifest.Documents))
	for _, entry := range manifest.Documents {
		if _, known := expected[entry.DocumentID]; !known {
			return nil, fmt.Errorf("situating context blurb references an unknown document %s", entry.DocumentID)
		}
		blurbs[entry.DocumentID] = entry.Blurb
		delete(expected, entry.DocumentID)
	}
	if len(expected) != 0 {
		return nil, errors.New("situating context is missing a blurb for at least one document")
	}
	return blurbs, nil
}

// situateEmbeddingInput prepends a document's committed blurb to its exact
// normalized payload bytes before embedding. With no blurb bound (the
// historical path) the raw payload is embedded unchanged.
func situateEmbeddingInput(payload []byte, blurbs map[string]string, documentID string) (string, error) {
	if blurbs == nil {
		return string(payload), nil
	}
	blurb, exists := blurbs[documentID]
	if !exists {
		return "", fmt.Errorf("missing situating blurb for %s", documentID)
	}
	return blurb + situatingBlurbSeparator + string(payload), nil
}
