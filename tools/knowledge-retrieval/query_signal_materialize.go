package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// QuerySignalMaterializeConfig pins every input needed to embed one literal
// query into an untrusted external QuerySignalArtifact for a specific hybrid
// candidate. It replaces the out-of-tree knowledge-embeddings query tool, which
// rejects shared multidomain candidates; the embedding runtime is not admitted,
// so the artifact stays state=candidate_input / authority_state=untrusted.
type QuerySignalMaterializeConfig struct {
	HybridCandidatePath string
	HybridCandidateHash string
	DenseArtifactPath   string
	DenseArtifactHash   string
	StoreRoot           string
	Query               string
	QueryInstruction    string
	Endpoint            string
	RequestModel        string
	TimeoutSeconds      int
	MaxRetries          int
}

// QuerySignalMaterializeResult reports the immutable artifact identity plus the
// whole-document SHA-256 the caller pins into `hybrid-query --query-artifact-sha256`.
type QuerySignalMaterializeResult struct {
	ArtifactID            string `json:"artifact_id"`
	ArtifactPayloadSHA256 string `json:"artifact_payload_sha256"`
	DocumentSHA256        string `json:"document_sha256"`
	ArtifactPath          string `json:"artifact_path"`
	HybridCandidateID     string `json:"hybrid_candidate_id"`
	DenseArtifactID       string `json:"dense_artifact_id"`
	Dimension             int    `json:"dimension"`
}

func runMaterializeQuerySignal(args []string) {
	flags := flag.NewFlagSet("materialize-query-signal", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := QuerySignalMaterializeConfig{}
	endpointEnv := flags.String("endpoint-env", "ARCHEION_EMBEDDINGS_ENDPOINT", "environment variable holding the exact /v3/embeddings URL")
	flags.StringVar(&config.HybridCandidatePath, "hybrid-candidate", "", "hybrid candidate manifest bound by the query signal")
	flags.StringVar(&config.HybridCandidateHash, "hybrid-candidate-sha256", "", "caller-pinned whole-document SHA-256 of the hybrid candidate")
	flags.StringVar(&config.DenseArtifactPath, "dense-artifact", "", "dense-vector artifact the hybrid candidate references")
	flags.StringVar(&config.DenseArtifactHash, "dense-artifact-sha256", "", "caller-pinned whole-document SHA-256 of the dense artifact")
	flags.StringVar(&config.StoreRoot, "store", "", "output query-signal artifact CAS")
	flags.StringVar(&config.Query, "query", "", "literal query bound by the artifact")
	flags.StringVar(&config.QueryInstruction, "query-instruction", "Given a web search query, retrieve relevant passages that answer the query", "asymmetric-retrieval query instruction recorded as dense_query_instruction")
	flags.StringVar(&config.RequestModel, "embedding-model", "", "model/graph name sent in the embeddings request body; defaults to the dense artifact model")
	flags.IntVar(&config.TimeoutSeconds, "timeout-seconds", 60, "per-request timeout seconds (1..300)")
	flags.IntVar(&config.MaxRetries, "max-retries", 3, "additional embedding attempts on transient failure (0..10)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	config.Endpoint = strings.TrimSpace(os.Getenv(*endpointEnv))
	result, err := MaterializeQuerySignal(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}

// MaterializeQuerySignal embeds the literal query in the Qwen3 asymmetric
// retrieval form, quantizes it against the dense artifact's declared scale and
// packages the result as a byte-reproducible QuerySignalArtifact for the
// no-reranking case. It self-validates against validateQuerySignals before
// writing, so an artifact that would fail the hybrid-query contract is never
// committed. All reranker fields stay empty (rerank-window 0).
func MaterializeQuerySignal(config QuerySignalMaterializeConfig) (QuerySignalMaterializeResult, error) {
	var zero QuerySignalMaterializeResult
	for name, value := range map[string]string{
		"hybrid-candidate": config.HybridCandidatePath, "hybrid-candidate-sha256": config.HybridCandidateHash,
		"dense-artifact": config.DenseArtifactPath, "dense-artifact-sha256": config.DenseArtifactHash,
		"store": config.StoreRoot, "query": config.Query, "query-instruction": config.QueryInstruction,
		"endpoint": config.Endpoint,
	} {
		if strings.TrimSpace(value) == "" {
			return zero, fmt.Errorf("%s is required", name)
		}
	}
	if !boundedMetadata(config.QueryInstruction) {
		return zero, errors.New("query-instruction is not bounded metadata")
	}
	if config.TimeoutSeconds < 1 || config.TimeoutSeconds > 300 {
		return zero, errors.New("timeout-seconds must be within 1..300")
	}
	if config.MaxRetries < 0 || config.MaxRetries > 10 {
		return zero, errors.New("max-retries must be within 0..10")
	}
	storeRoot, err := filepath.Abs(config.StoreRoot)
	if err != nil || validateNoSymlinkExistingPrefix(storeRoot) != nil {
		return zero, errors.New("store path is unavailable")
	}

	hybridBytes, err := readStableFile(config.HybridCandidatePath, "hybrid candidate", maxManifestBytes)
	if err != nil {
		return zero, fmt.Errorf("read hybrid candidate: %w", err)
	}
	if digestBytes(hybridBytes) != config.HybridCandidateHash {
		return zero, errors.New("hybrid candidate document does not match caller pin")
	}
	var hybrid HybridCandidateManifest
	if err := decodeStrictCanonical(hybridBytes, &hybrid); err != nil || validateHybridCandidate(hybrid) != nil {
		return zero, errors.New("hybrid candidate is invalid")
	}

	denseBytes, err := readStableFile(config.DenseArtifactPath, "dense artifact", maxDenseArtifactBytes)
	if err != nil {
		return zero, fmt.Errorf("read dense artifact: %w", err)
	}
	if digestBytes(denseBytes) != config.DenseArtifactHash {
		return zero, errors.New("dense artifact document does not match caller pin")
	}
	var dense DenseVectorArtifact
	if err := decodeStrictCanonical(denseBytes, &dense); err != nil {
		return zero, errors.New("dense artifact is invalid")
	}
	coreDigest, err := json.Marshal(dense.DenseVectorArtifactCore)
	if err != nil || dense.ArtifactPayloadSHA256 != digestBytes(coreDigest) || dense.ArtifactID != "dense-vector-artifact:"+dense.ArtifactPayloadSHA256 {
		return zero, errors.New("dense artifact identity mismatch")
	}
	// The hybrid must bind this exact dense artifact: identical whole-document
	// pin and artifact identity. loadHybridCandidate resolves loaded.dense from
	// hybrid.DenseArtifactPath/SHA256 and validateLoadedHybridLineage requires
	// hybrid.DenseArtifactID == dense.ArtifactID, so the emitted DenseArtifactID
	// equals what the hybrid references only when both hold here.
	if config.DenseArtifactHash != hybrid.DenseArtifactSHA256 || dense.ArtifactID != hybrid.DenseArtifactID {
		return zero, errors.New("dense artifact is not bound by the hybrid candidate")
	}
	if dense.Dimension < 1 {
		return zero, errors.New("dense artifact declares no dimension")
	}
	if config.RequestModel == "" {
		config.RequestModel = dense.ModelID
	}
	if strings.TrimSpace(config.RequestModel) == "" {
		return zero, errors.New("embedding-model is required")
	}

	// Corpus documents were embedded raw (document_instruction "none"); the query
	// must use the Qwen3 asymmetric-retrieval form to route cross-authority.
	embedInput := "Instruct: " + config.QueryInstruction + "\nQuery: " + config.Query
	denseConfig := DenseMaterializeConfig{
		Endpoint: config.Endpoint, RequestModel: config.RequestModel,
		TimeoutSeconds: config.TimeoutSeconds, BatchSize: 1,
	}
	var vectors [][]float64
	var embErr error
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		vectors, embErr = embedDenseInputs(denseConfig, []string{embedInput})
		if embErr == nil {
			break
		}
	}
	if embErr != nil {
		return zero, embErr
	}
	if len(vectors) != 1 {
		return zero, errors.New("embedding endpoint returned a mismatched vector count")
	}
	queryVector, err := quantizeUnitVector(vectors[0], dense.QuantizationScale)
	if err != nil {
		return zero, fmt.Errorf("quantize query: %w", err)
	}
	if len(queryVector) != dense.Dimension {
		return zero, errors.New("query embedding dimension does not match the dense artifact")
	}

	core := QuerySignalArtifactCore{
		SchemaVersion: retrievalSchemaVersion, ArtifactKind: querySignalArtifactKind,
		State: "candidate_input", AuthorityState: "untrusted_candidate_input",
		HybridCandidateID: hybrid.ManifestID, QuerySHA256: digestBytes([]byte(config.Query)),
		DenseArtifactID: dense.ArtifactID, DenseModelID: dense.ModelID,
		DenseModelRevision: dense.ModelRevision, DenseModelArtifactSHA256: dense.ModelArtifactSHA256,
		DenseTokenizerID: dense.TokenizerID, DenseTokenizerSHA256: dense.TokenizerSHA256,
		EmbeddingProfile: dense.EmbeddingProfile, DenseQueryInstruction: config.QueryInstruction,
		DenseDocumentInstruction: dense.DocumentInstruction, VectorEncoding: dense.VectorEncoding,
		Normalization: dense.Normalization, QuantizationScale: dense.QuantizationScale,
		Dimension: dense.Dimension, QueryVector: queryVector, RerankingRequested: false,
		Scores: []RerankerDocumentScore{},
	}
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return zero, err
	}
	payloadDigest := digestBytes(coreBytes)
	signal := QuerySignalArtifact{
		ArtifactID:              "query-signal-artifact:" + payloadDigest,
		ArtifactPayloadSHA256:   payloadDigest,
		QuerySignalArtifactCore: core,
	}
	// Self-validate against the exact hybrid-query contract. validateQuerySignals
	// reads only loaded.hybrid.ManifestID and loaded.dense.* in the no-reranking
	// path, so a minimal loaded candidate is sufficient and complete here.
	loaded := loadedHybridCandidate{hybrid: hybrid, dense: dense}
	if err := validateQuerySignals(signal, loaded, config.Query, false); err != nil {
		return zero, fmt.Errorf("materialized query signal fails the hybrid-query contract: %w", err)
	}

	fileBytes, err := marshalDocument(signal)
	if err != nil {
		return zero, err
	}
	relative, err := contentObjectPath("query-signals", payloadDigest)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, relative, fileBytes); err != nil {
		return zero, fmt.Errorf("commit query signal: %w", err)
	}
	return QuerySignalMaterializeResult{
		ArtifactID: signal.ArtifactID, ArtifactPayloadSHA256: payloadDigest,
		DocumentSHA256: digestBytes(fileBytes), ArtifactPath: filepath.Join(storeRoot, relative),
		HybridCandidateID: hybrid.ManifestID, DenseArtifactID: dense.ArtifactID, Dimension: dense.Dimension,
	}, nil
}
