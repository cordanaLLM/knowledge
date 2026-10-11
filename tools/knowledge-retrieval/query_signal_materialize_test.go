package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// stubEmbeddingServer returns the fixed float vector for every requested input,
// mimicking the /v3/embeddings contract embedDenseInputs speaks.
func stubEmbeddingServer(t *testing.T, vector []float64) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model string   `json:"model"`
			Input []string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		response := embeddingResponse{}
		for index := range request.Input {
			response.Data = append(response.Data, struct {
				Index     int       `json:"index"`
				Embedding []float64 `json:"embedding"`
			}{Index: index, Embedding: vector})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestMaterializeQuerySignalPassesHybridQueryContract(t *testing.T) {
	fx := newHybridTestFixture(t)
	server := stubEmbeddingServer(t, []float64{0.0, 1.0})
	config := QuerySignalMaterializeConfig{
		HybridCandidatePath: fx.hybrid.ManifestPath, HybridCandidateHash: fileDigest(fx.hybrid.ManifestPath),
		DenseArtifactPath: fx.densePath, DenseArtifactHash: fx.denseHash,
		StoreRoot: t.TempDir(), Query: "alpha",
		QueryInstruction: "Given a web search query, retrieve relevant passages that answer the query",
		Endpoint:         server.URL, RequestModel: fx.dense.ModelID,
		TimeoutSeconds: 60, MaxRetries: 0,
	}
	result, err := MaterializeQuerySignal(config)
	if err != nil {
		t.Fatal(err)
	}
	if result.HybridCandidateID != fx.hybrid.Manifest.ManifestID || result.DenseArtifactID != fx.dense.ArtifactID || result.Dimension != fx.dense.Dimension {
		t.Fatalf("materialized identity mismatch: %#v", result)
	}

	data, err := os.ReadFile(result.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(data) != result.DocumentSHA256 {
		t.Fatalf("committed document sha mismatch")
	}
	var signal QuerySignalArtifact
	if err := decodeStrictCanonical(data, &signal); err != nil {
		t.Fatalf("committed query signal is not canonical: %v", err)
	}
	loaded := loadedHybridCandidate{hybrid: fx.hybrid.Manifest, dense: fx.dense}
	if err := validateQuerySignals(signal, loaded, "alpha", false); err != nil {
		t.Fatalf("materialized query signal rejected by contract: %v", err)
	}
	if signal.RerankingRequested || signal.RerankerScoreScale != 0 || signal.Scores == nil || len(signal.Scores) != 0 {
		t.Fatalf("no-reranking contract violated: %#v", signal.QuerySignalArtifactCore)
	}
	if signal.QuerySHA256 != digestBytes([]byte("alpha")) || signal.DenseQueryInstruction != config.QueryInstruction {
		t.Fatalf("query binding mismatch: %#v", signal.QuerySignalArtifactCore)
	}

	// Every tamper must fail closed against the same loaded candidate.
	for name, mutate := range map[string]func(*QuerySignalArtifact){
		"tampered_vector": func(s *QuerySignalArtifact) { s.QueryVector = []int16{1, 1} },
		"wrong_hybrid_id": func(s *QuerySignalArtifact) { s.HybridCandidateID = "hybrid-retrieval-candidate:sha256:" + "0" },
		"nonempty_scores": func(s *QuerySignalArtifact) {
			s.Scores = []RerankerDocumentScore{{DocumentID: fx.alphaDocID, Score: 1}}
		},
		"wrong_query_digest": func(s *QuerySignalArtifact) { s.QuerySHA256 = digestBytes([]byte("beta")) },
	} {
		tampered := signal
		tampered.Scores = append([]RerankerDocumentScore{}, signal.Scores...)
		tampered.QueryVector = append([]int16(nil), signal.QueryVector...)
		mutate(&tampered)
		resealQuerySignals(&tampered)
		if err := validateQuerySignals(tampered, loaded, "alpha", false); err == nil {
			t.Fatalf("%s: tampered query signal accepted", name)
		}
	}
}

func TestMaterializeQuerySignalRejectsUnboundDenseArtifact(t *testing.T) {
	fx := newHybridTestFixture(t)
	server := stubEmbeddingServer(t, []float64{0.0, 1.0})
	// A well-formed hybrid whose bound dense pin does not match the supplied
	// dense document must be refused before any embedding is committed.
	config := QuerySignalMaterializeConfig{
		HybridCandidatePath: fx.hybrid.ManifestPath, HybridCandidateHash: fileDigest(fx.hybrid.ManifestPath),
		DenseArtifactPath: fx.densePath, DenseArtifactHash: "sha256:" + repeat64('a'),
		StoreRoot: t.TempDir(), Query: "alpha",
		QueryInstruction: "Given a web search query, retrieve relevant passages that answer the query",
		Endpoint:         server.URL, RequestModel: fx.dense.ModelID, TimeoutSeconds: 60, MaxRetries: 0,
	}
	if _, err := MaterializeQuerySignal(config); err == nil {
		t.Fatal("materializer accepted a dense document mismatching the caller pin")
	}
}

func repeat64(b byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = b
	}
	return string(out)
}
