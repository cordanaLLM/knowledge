package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DenseMaterializeConfig pins every input needed to embed a lexical candidate's
// document set into an untrusted external dense-vector artifact. It replaces the
// out-of-tree knowledge-embeddings tool: the embedding runtime is not admitted,
// so the artifact stays state=candidate_input / authority_state=untrusted.
type DenseMaterializeConfig struct {
	CandidatePath       string
	CandidateHash       string
	RetrievalStore      string
	EvidenceStore       string
	StoreRoot           string
	ModelID             string
	ModelRevision       string
	ModelTreeSHA256     string
	TokenizerID         string
	TokenizerTreeSHA256 string
	EmbeddingProfile    string
	DocumentInstruction string
	Endpoint            string
	RequestModel        string
	BatchSize           int
	TimeoutSeconds      int
	MaxDenseDocuments   int
	MaxDenseDimension   int
	// SituatingContextPath/Hash optionally pin a committed SituatingContextManifest
	// (index-time Contextual Retrieval): a fixed, model-generated blurb per
	// document, prepended to that document's exact normalized payload before
	// embedding. Both empty reproduces the historical raw-payload embedding
	// input byte-for-byte; the embedding input is not part of any downstream
	// artifact identity, so this never changes the dense/hybrid contract.
	SituatingContextPath string
	SituatingContextHash string
}

// DenseMaterializeResult reports the immutable artifact identity plus the
// whole-document SHA-256 the caller pins into `hybridize --dense-artifact-sha256`.
type DenseMaterializeResult struct {
	ArtifactID            string `json:"artifact_id"`
	ArtifactPayloadSHA256 string `json:"artifact_payload_sha256"`
	DocumentSHA256        string `json:"document_sha256"`
	ArtifactPath          string `json:"artifact_path"`
	DocumentCount         int    `json:"document_count"`
	Dimension             int    `json:"dimension"`
}

func runMaterializeDenseArtifact(args []string) {
	flags := flag.NewFlagSet("materialize-dense-artifact", flag.ContinueOnError)
	config := DenseMaterializeConfig{}
	endpointEnv := flags.String("endpoint-env", "ARCHEION_EMBEDDINGS_ENDPOINT", "environment variable holding the exact /v3/embeddings URL")
	flags.StringVar(&config.CandidatePath, "candidate", "", "lexical candidate manifest")
	flags.StringVar(&config.CandidateHash, "candidate-sha256", "", "caller-pinned whole-document SHA-256 of the lexical candidate")
	flags.StringVar(&config.RetrievalStore, "retrieval-store", "", "lexical retrieval CAS")
	flags.StringVar(&config.EvidenceStore, "evidence-store", "", "normalized evidence CAS")
	flags.StringVar(&config.StoreRoot, "store", "", "output dense artifact CAS")
	flags.StringVar(&config.ModelID, "model-id", "", "exact requested model ID")
	flags.StringVar(&config.ModelRevision, "model-revision", "", "exact immutable model revision")
	flags.StringVar(&config.ModelTreeSHA256, "model-tree-sha256", "", "exact model artifact/tree SHA-256")
	flags.StringVar(&config.TokenizerID, "tokenizer-id", "", "exact tokenizer ID")
	flags.StringVar(&config.TokenizerTreeSHA256, "tokenizer-tree-sha256", "", "exact tokenizer artifact/tree SHA-256")
	flags.StringVar(&config.EmbeddingProfile, "embedding-profile", "", "versioned asymmetric embedding profile")
	flags.StringVar(&config.DocumentInstruction, "document-instruction", "none", "document instruction marker (asymmetric documents get none)")
	flags.StringVar(&config.RequestModel, "embedding-model", "", "model/graph name sent in the embeddings request body")
	flags.IntVar(&config.BatchSize, "batch-size", 8, "documents per embedding request (1..128)")
	flags.IntVar(&config.TimeoutSeconds, "timeout-seconds", 60, "per-request timeout seconds (1..300)")
	flags.IntVar(&config.MaxDenseDocuments, "max-dense-documents", 0, "maximum dense documents")
	flags.IntVar(&config.MaxDenseDimension, "max-dense-dimension", 0, "maximum dense vector dimension")
	flags.StringVar(&config.SituatingContextPath, "situating-context", "", "optional strict canonical SituatingContextManifest JSON (index-time Contextual Retrieval blurbs)")
	flags.StringVar(&config.SituatingContextHash, "situating-context-sha256", "", "caller-pinned whole-document SHA-256 of the situating context manifest; required iff --situating-context is set")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	config.Endpoint = strings.TrimSpace(os.Getenv(*endpointEnv))
	if config.RequestModel == "" {
		config.RequestModel = config.ModelID
	}
	result, err := MaterializeDenseArtifact(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}

// MaterializeDenseArtifact embeds every candidate document in strict document-ID
// order and packages the result as a byte-reproducible DenseVectorArtifact. It
// self-validates against validateDenseArtifact before writing, so an artifact
// that would fail the hybridize contract is never committed.
func MaterializeDenseArtifact(config DenseMaterializeConfig) (DenseMaterializeResult, error) {
	var zero DenseMaterializeResult
	for name, value := range map[string]string{
		"candidate": config.CandidatePath, "candidate-sha256": config.CandidateHash,
		"retrieval-store": config.RetrievalStore, "evidence-store": config.EvidenceStore,
		"store": config.StoreRoot, "model-id": config.ModelID, "model-revision": config.ModelRevision,
		"model-tree-sha256": config.ModelTreeSHA256, "tokenizer-id": config.TokenizerID,
		"tokenizer-tree-sha256": config.TokenizerTreeSHA256, "embedding-profile": config.EmbeddingProfile,
		"document-instruction": config.DocumentInstruction, "endpoint": config.Endpoint,
		"embedding-model": config.RequestModel,
	} {
		if strings.TrimSpace(value) == "" {
			return zero, fmt.Errorf("%s is required", name)
		}
	}
	if config.BatchSize < 1 || config.BatchSize > 128 {
		return zero, errors.New("batch-size must be within 1..128")
	}
	if config.TimeoutSeconds < 1 || config.TimeoutSeconds > 300 {
		return zero, errors.New("timeout-seconds must be within 1..300")
	}
	maxDocuments, maxDimension, err := normalizeDenseLimits(config.MaxDenseDocuments, config.MaxDenseDimension)
	if err != nil {
		return zero, err
	}
	storeRoot, err := filepath.Abs(config.StoreRoot)
	if err != nil || validateNoSymlinkExistingPrefix(storeRoot) != nil {
		return zero, errors.New("store path is unavailable")
	}
	evidenceRoot, err := filepath.Abs(config.EvidenceStore)
	if err != nil {
		return zero, errors.New("evidence store path is unavailable")
	}
	retrievalRoot, err := filepath.Abs(config.RetrievalStore)
	if err != nil {
		return zero, errors.New("retrieval store path is unavailable")
	}

	candidateBytes, err := readStableFile(config.CandidatePath, "lexical candidate", maxManifestBytes)
	if err != nil {
		return zero, fmt.Errorf("read lexical candidate: %w", err)
	}
	if digestBytes(candidateBytes) != config.CandidateHash {
		return zero, errors.New("lexical candidate document does not match caller pin")
	}
	var candidate CandidateManifest
	if err := decodeStrictCanonical(candidateBytes, &candidate); err != nil || validateCandidate(candidate) != nil {
		return zero, errors.New("lexical candidate is invalid")
	}
	if candidate.DocumentCount < 1 || candidate.DocumentCount > maxDocuments {
		return zero, errors.New("lexical candidate document count exceeds dense bound")
	}
	index, err := readBoundLexicalIndex(retrievalRoot, candidate)
	if err != nil {
		return zero, err
	}

	if (config.SituatingContextPath == "") != (config.SituatingContextHash == "") {
		return zero, errors.New("situating-context path and caller pin must both be present or absent")
	}
	var situatingBlurbs map[string]string
	if config.SituatingContextPath != "" {
		situatingBytes, err := readStableFile(config.SituatingContextPath, "situating context", maxSituatingContextBytes)
		if err != nil {
			return zero, fmt.Errorf("read situating context: %w", err)
		}
		if digestBytes(situatingBytes) != config.SituatingContextHash {
			return zero, errors.New("situating context document does not match caller pin")
		}
		var situating SituatingContextManifest
		if err := decodeStrictCanonical(situatingBytes, &situating); err != nil {
			return zero, errors.New("situating context is not strict canonical JSON")
		}
		situatingBlurbs, err = resolveSituatingBlurbs(situating, candidate.ManifestID, config.CandidateHash, index.Documents)
		if err != nil {
			return zero, fmt.Errorf("situating context: %w", err)
		}
	}

	// Resolve every document to its exact normalized payload, in strict
	// document-ID order (the dense contract requires it).
	documents := make([]IndexedDocument, len(index.Documents))
	copy(documents, index.Documents)
	sort.Slice(documents, func(i, j int) bool { return documents[i].DocumentID < documents[j].DocumentID })
	inputs := make([]string, 0, len(documents))
	for _, document := range documents {
		payloadPath := filepath.Join(evidenceRoot, filepath.FromSlash(document.Evidence.PayloadObjectPath))
		if !isWithin(evidenceRoot, payloadPath) {
			return zero, errors.New("normalized payload escaped its evidence store")
		}
		payload, err := verifyFileDigest(payloadPath, document.Evidence.PayloadSHA256, document.Evidence.PayloadByteSize)
		if err != nil {
			return zero, fmt.Errorf("normalized payload for %s: %w", document.DocumentID, err)
		}
		input, err := situateEmbeddingInput(payload, situatingBlurbs, document.DocumentID)
		if err != nil {
			return zero, fmt.Errorf("situate %s: %w", document.DocumentID, err)
		}
		inputs = append(inputs, input)
	}

	vectors, err := embedDenseInputs(config, inputs)
	if err != nil {
		return zero, err
	}
	if len(vectors) != len(documents) {
		return zero, errors.New("embedding endpoint returned a mismatched vector count")
	}
	dimension := len(vectors[0])
	if dimension < 1 || dimension > maxDimension {
		return zero, errors.New("embedding dimension is out of bounds")
	}
	denseDocuments := make([]DenseDocumentVector, len(documents))
	for i, document := range documents {
		if len(vectors[i]) != dimension {
			return zero, errors.New("embedding vectors have inconsistent dimension")
		}
		values, err := quantizeUnitVector(vectors[i], denseQuantizationScale)
		if err != nil {
			return zero, fmt.Errorf("quantize %s: %w", document.DocumentID, err)
		}
		denseDocuments[i] = DenseDocumentVector{DocumentID: document.DocumentID, Values: values}
	}

	core := DenseVectorArtifactCore{
		SchemaVersion: retrievalSchemaVersion, ArtifactKind: "external_dense_document_vectors",
		State: "candidate_input", AuthorityState: "untrusted_candidate_input",
		LexicalCandidateID: candidate.ManifestID, LexicalIndexID: candidate.LexicalIndexID,
		EvidenceManifestID: candidate.EvidenceManifestID, Lineages: candidate.Lineages,
		ModelID: config.ModelID, ModelRevision: config.ModelRevision, ModelArtifactSHA256: config.ModelTreeSHA256,
		TokenizerID: config.TokenizerID, TokenizerSHA256: config.TokenizerTreeSHA256,
		EmbeddingProfile: config.EmbeddingProfile, DocumentInstruction: config.DocumentInstruction,
		VectorEncoding: denseVectorEncoding, Normalization: denseVectorNormalization,
		QuantizationScale: denseQuantizationScale, Dimension: dimension,
		DocumentCount: len(denseDocuments), Documents: denseDocuments,
	}
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return zero, err
	}
	payloadDigest := digestBytes(coreBytes)
	dense := DenseVectorArtifact{
		ArtifactID:              "dense-vector-artifact:" + payloadDigest,
		ArtifactPayloadSHA256:   payloadDigest,
		DenseVectorArtifactCore: core,
	}
	if err := validateDenseArtifact(dense, candidate, index, maxDocuments, maxDimension); err != nil {
		return zero, fmt.Errorf("materialized dense artifact fails the hybridize contract: %w", err)
	}

	fileBytes, err := marshalDocument(dense)
	if err != nil {
		return zero, err
	}
	relative, err := contentObjectPath("dense-artifacts", payloadDigest)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, relative, fileBytes); err != nil {
		return zero, fmt.Errorf("commit dense artifact: %w", err)
	}
	return DenseMaterializeResult{
		ArtifactID: dense.ArtifactID, ArtifactPayloadSHA256: payloadDigest,
		DocumentSHA256: digestBytes(fileBytes), ArtifactPath: filepath.Join(storeRoot, relative),
		DocumentCount: len(denseDocuments), Dimension: dimension,
	}, nil
}

// quantizeUnitVector L2-normalizes a float embedding and symmetrically quantizes
// it to signed int16 at the declared scale, matching the dense vector contract
// (l2_unit_before_symmetric_int16_quantization). MinInt16 is excluded.
func quantizeUnitVector(vector []float64, scale int) ([]int16, error) {
	if len(vector) < 1 {
		return nil, errors.New("empty embedding vector")
	}
	var squared float64
	for _, value := range vector {
		squared += value * value
	}
	norm := math.Sqrt(squared)
	if !(norm > 0) || math.IsInf(norm, 0) || math.IsNaN(norm) {
		return nil, errors.New("embedding vector is not a finite non-zero vector")
	}
	limit := float64(scale)
	values := make([]int16, len(vector))
	for i, value := range vector {
		scaled := math.Round(value / norm * limit)
		if scaled > limit {
			scaled = limit
		}
		if scaled < -limit {
			scaled = -limit
		}
		values[i] = int16(scaled)
	}
	return values, nil
}

type embeddingResponse struct {
	Data []struct {
		Index     int       `json:"index"`
		Embedding []float64 `json:"embedding"`
	} `json:"data"`
}

// embedDenseInputs sends the exact UTF-8 payloads to the /v3/embeddings endpoint
// in bounded batches (no instruction or wrapper; asymmetric documents get none)
// and returns one float vector per input in input order.
func embedDenseInputs(config DenseMaterializeConfig, inputs []string) ([][]float64, error) {
	client := &http.Client{Timeout: time.Duration(config.TimeoutSeconds) * time.Second}
	vectors := make([][]float64, 0, len(inputs))
	for start := 0; start < len(inputs); start += config.BatchSize {
		end := start + config.BatchSize
		if end > len(inputs) {
			end = len(inputs)
		}
		batch := inputs[start:end]
		body, err := json.Marshal(map[string]any{"model": config.RequestModel, "input": batch, "encoding_format": "float"})
		if err != nil {
			return nil, err
		}
		request, err := http.NewRequest(http.MethodPost, config.Endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("embedding request failed: %w", err)
		}
		decoded := embeddingResponse{}
		decodeErr := json.NewDecoder(response.Body).Decode(&decoded)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("embedding endpoint returned status %d", response.StatusCode)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("embedding response is not valid JSON: %w", decodeErr)
		}
		if len(decoded.Data) != len(batch) {
			return nil, errors.New("embedding response cardinality does not match the request")
		}
		sort.Slice(decoded.Data, func(i, j int) bool { return decoded.Data[i].Index < decoded.Data[j].Index })
		for offset, item := range decoded.Data {
			if item.Index != offset {
				return nil, errors.New("embedding response indices are not contiguous")
			}
			vectors = append(vectors, item.Embedding)
		}
	}
	return vectors, nil
}
