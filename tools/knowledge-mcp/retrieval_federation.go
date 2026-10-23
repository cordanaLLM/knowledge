package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxRetrievalCatalogBytes       = 256 << 10
	maxRetrievalAdmissionBytes     = 1 << 20
	maxRetrievalFederationLanes    = 8
	maxRetrievalFederationWorker   = 4
	maxFederationDiagnosticBytes   = 2048
	retrievalFederationLaneTimeout = 20 * time.Second
	retrievalFederationWaveCount   = (maxRetrievalFederationLanes + maxRetrievalFederationWorker - 1) / maxRetrievalFederationWorker
	retrievalFederationChildBudget = time.Duration(retrievalFederationWaveCount) * retrievalFederationLaneTimeout
	retrievalFederationMCPBudget   = 60 * time.Second
)

var retrievalLaneIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type retrievalFederationCatalog struct {
	SchemaVersion string                    `json:"schema_version"`
	RecordKind    string                    `json:"record_kind"`
	Lanes         []retrievalFederationLane `json:"lanes"`
}

type retrievalFederationLane struct {
	LaneID                      string `json:"lane_id"`
	RetrievalExecutable         string `json:"retrieval_executable"`
	RetrievalExecutableSHA256   string `json:"retrieval_executable_sha256"`
	RetrievalStore              string `json:"retrieval_store"`
	RetrievalState              string `json:"retrieval_state"`
	RetrievalEvidenceStore      string `json:"retrieval_evidence_store"`
	RetrievalAdmissionPolicy    string `json:"retrieval_admission_policy"`
	RetrievalAdmissionPolicySHA string `json:"retrieval_admission_policy_sha256"`
	AdmissionSourceID           string `json:"-"`
}

type retrievalAdmissionIdentity struct {
	PolicyID            string `json:"policy_id"`
	PolicyPayloadSHA256 string `json:"policy_payload_sha256"`
	SchemaVersion       string `json:"schema_version"`
	PolicyKind          string `json:"policy_kind"`
	State               string `json:"state"`
	SnapshotManifestID  string `json:"snapshot_manifest_id"`
	EvidenceManifestID  string `json:"evidence_manifest_id"`
	SnapshotID          string `json:"snapshot_id"`
	SourceID            string `json:"source_id"`
	ComponentID         string `json:"component_id"`
	ComponentVersionID  string `json:"component_version_id"`
	AccessScope         string `json:"access_scope"`
	RetrievalAllowed    bool   `json:"retrieval_allowed"`
	SourceState         string `json:"source_state"`
	DeletionState       string `json:"deletion_state"`
	Tombstone           bool   `json:"tombstone"`
	EvaluatedAt         string `json:"evaluated_at"`
	FreshUntil          string `json:"fresh_until"`
}

type federatedRetrievalLaneMatch struct {
	LaneID      string `json:"lane_id"`
	Rank        int    `json:"rank"`
	SourceScore int    `json:"source_score"`
}

type federatedRetrievalHit struct {
	Score            int                           `json:"score"`
	BestLaneRank     int                           `json:"best_lane_rank"`
	LaneMatches      []federatedRetrievalLaneMatch `json:"lane_matches"`
	MatchedTerms     []string                      `json:"matched_terms"`
	Evidence         currentRetrievalEvidence      `json:"evidence"`
	Excerpt          string                        `json:"excerpt"`
	ExcerptTruncated bool                          `json:"excerpt_truncated"`
}

type federationLaneOutcome struct {
	lane    retrievalFederationLane
	outcome toolOutcome
}

type federationAccumulator struct {
	hit   federatedRetrievalHit
	terms map[string]struct{}
}

func (provider *retrievalProvider) searchFederation(ctx context.Context, query string, limit, maxExcerptBytes int, asOf string) toolOutcome {
	if ctx == nil {
		ctx = context.Background()
	}
	catalog, err := provider.loadRetrievalCatalog()
	if err != nil {
		return provider.federationConfigurationFailure(asOf, err)
	}
	fixedTime, err := time.Parse("2006-01-02T15:04:05Z", asOf)
	if err != nil {
		return provider.federationConfigurationFailure(asOf, errors.New("broker time is not canonical UTC"))
	}

	queryJSON, _ := json.Marshal(query)
	limitJSON, _ := json.Marshal(limit)
	excerptJSON, _ := json.Marshal(maxExcerptBytes)
	arguments := map[string]json.RawMessage{
		"query":             queryJSON,
		"limit":             limitJSON,
		"max_excerpt_bytes": excerptJSON,
	}
	outcomes := make([]federationLaneOutcome, len(catalog.Lanes))
	jobs := make(chan int)
	workers := len(catalog.Lanes)
	if workers > maxRetrievalFederationWorker {
		workers = maxRetrievalFederationWorker
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for index := range jobs {
				lane := catalog.Lanes[index]
				laneProvider := &retrievalProvider{
					configured: true,
					executable: lane.RetrievalExecutable, executableSHA256: lane.RetrievalExecutableSHA256,
					store: lane.RetrievalStore, state: lane.RetrievalState, evidenceStore: lane.RetrievalEvidenceStore,
					admissionPolicy: lane.RetrievalAdmissionPolicy, admissionPolicyHash: lane.RetrievalAdmissionPolicySHA,
					commandTimeout: retrievalFederationLaneTimeout,
					now:            func() time.Time { return fixedTime },
				}
				outcomes[index] = federationLaneOutcome{lane: lane, outcome: laneProvider.search(ctx, arguments)}
			}
		}()
	}
	for index := range catalog.Lanes {
		// Stop feeding lanes once the caller is gone; workers still drain and
		// wait, so every started child is reaped before this returns.
		select {
		case jobs <- index:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wait.Wait()
	if ctx.Err() != nil {
		return provider.federationFailure(asOf, "federation retrieval was cancelled by the caller", "federation_cancelled")
	}

	// The externally pinned catalog is the federation authority. Discard all
	// evidence if its exact bytes cease to validate during the operation.
	if _, err := provider.loadRetrievalCatalog(); err != nil {
		return provider.federationConfigurationFailure(asOf, fmt.Errorf("catalog changed during retrieval: %w", err))
	}
	return provider.fuseFederation(outcomes, limit, asOf)
}

func (provider *retrievalProvider) federationConfigurationFailure(asOf string, err error) toolOutcome {
	return provider.federationFailure(asOf, "validate retrieval federation catalog: "+err.Error(), "federation_catalog_invalid")
}

// federationFailure is the single evidence-free federation failure shape: no
// lanes, no results, never a silently-empty success.
func (provider *retrievalProvider) federationFailure(asOf, message, errorCode string) toolOutcome {
	return errorOutcome(stateBackendUnavailable, message, map[string]any{
		"result_state":        "backend_unavailable",
		"retrieval_state":     "federated_unavailable",
		"authority_state":     "unavailable",
		"profile":             "deterministic_rank_fusion",
		"serving_eligible":    false,
		"current_eligible":    false,
		"error_code":          errorCode,
		"failure_scope":       "federation",
		"observed_at":         asOf,
		"time_source":         "broker_host_clock_utc",
		"principal_scope":     "public",
		"catalog_sha256":      "sha256:" + provider.catalogSHA256,
		"lane_count":          0,
		"current_lane_count":  0,
		"degraded_lane_count": 0,
		"results":             []federatedRetrievalHit{},
		"lanes":               []map[string]any{},
	})
}

func (provider *retrievalProvider) loadRetrievalCatalog() (*retrievalFederationCatalog, error) {
	if provider.catalog == "" || !validSHA256Hex(provider.catalogSHA256) {
		return nil, errors.New("catalog path or SHA-256 pin is missing")
	}
	if !filepath.IsAbs(provider.catalog) || filepath.Clean(provider.catalog) != provider.catalog {
		return nil, errors.New("catalog path is not canonical absolute")
	}
	if err := validateDirectoryPathNoSymlinks(filepath.Dir(provider.catalog)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(provider.catalog) // #nosec G703 -- catalog is the operator-selected absolute path; regular-file, symlink, permission and SHA-256 checks follow.
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 {
		return nil, errors.New("catalog is not an immutable regular file")
	}
	data, err := readBoundRegular(provider.catalog, maxRetrievalCatalogBytes, true)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != provider.catalogSHA256 {
		return nil, errors.New("catalog SHA-256 does not match the operator pin")
	}
	var catalog retrievalFederationCatalog
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	if err := decodeStrictTyped(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	if err := validateRetrievalFederationCatalog(catalog); err != nil {
		return nil, err
	}
	seenSources := make(map[string]string, len(catalog.Lanes))
	for index := range catalog.Lanes {
		sourceID, err := loadRetrievalAdmissionSource(catalog.Lanes[index])
		if err != nil {
			return nil, fmt.Errorf("lane %q admission policy: %w", catalog.Lanes[index].LaneID, err)
		}
		if owner, duplicate := seenSources[sourceID]; duplicate {
			return nil, fmt.Errorf("lanes %q and %q bind the same admission-policy source_id", owner, catalog.Lanes[index].LaneID)
		}
		seenSources[sourceID] = catalog.Lanes[index].LaneID
		catalog.Lanes[index].AdmissionSourceID = sourceID
	}
	return &catalog, nil
}

func loadRetrievalAdmissionSource(lane retrievalFederationLane) (string, error) {
	if err := validateDirectoryPathNoSymlinks(filepath.Dir(lane.RetrievalAdmissionPolicy)); err != nil {
		return "", err
	}
	info, err := os.Lstat(lane.RetrievalAdmissionPolicy)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 {
		return "", errors.New("policy is not an immutable regular file")
	}
	data, err := readBoundRegular(lane.RetrievalAdmissionPolicy, maxRetrievalAdmissionBytes, true)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != lane.RetrievalAdmissionPolicySHA {
		return "", errors.New("policy SHA-256 does not match the catalog pin")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return "", err
	}
	var policy retrievalAdmissionIdentity
	if err := decodeStrictTyped(data, &policy); err != nil {
		return "", err
	}
	if policy.SchemaVersion != "1.0.0" || policy.PolicyKind != "public_retrieval_admission" || policy.State != "active" ||
		policy.AccessScope != "public" || !policy.RetrievalAllowed || policy.SourceState != "present" ||
		policy.DeletionState != "active" || policy.Tombstone {
		return "", errors.New("policy does not authorize one active public source")
	}
	if !validRetrievalDigest(policy.PolicyPayloadSHA256) || policy.PolicyID != "retrieval-admission:"+policy.PolicyPayloadSHA256 ||
		!validRetrievalObjectID(policy.SnapshotManifestID, "snapshot-manifest:") ||
		!validRetrievalObjectID(policy.EvidenceManifestID, "evidence-manifest:") ||
		!validRetrievalString(policy.SnapshotID, 4096, false) || !validRetrievalString(policy.SourceID, 4096, false) ||
		!validRetrievalString(policy.ComponentID, 4096, false) || !validRetrievalString(policy.ComponentVersionID, 4096, false) ||
		!canonicalRetrievalTime(policy.EvaluatedAt) || !canonicalRetrievalTime(policy.FreshUntil) || derivedRetrievalAuthority(policy.SourceID) {
		return "", errors.New("policy source identity or lineage is invalid")
	}
	return policy.SourceID, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("unsupported JSON delimiter")
		}
		expected := json.Delim('}')
		if delimiter == '[' {
			expected = ']'
		}
		closing, err := decoder.Token()
		if err != nil || closing != expected {
			return errors.New("JSON compound value is not closed")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return err
	}
	return nil
}

func validateRetrievalFederationCatalog(catalog retrievalFederationCatalog) error {
	if catalog.SchemaVersion != "1.0.0" || catalog.RecordKind != "retrieval_federation_catalog" {
		return errors.New("catalog schema_version or record_kind is unsupported")
	}
	if len(catalog.Lanes) < 1 || len(catalog.Lanes) > maxRetrievalFederationLanes {
		return fmt.Errorf("catalog must contain between 1 and %d lanes", maxRetrievalFederationLanes)
	}
	seenStates := make(map[string]string, len(catalog.Lanes))
	previousLaneID := ""
	for index, lane := range catalog.Lanes {
		if !retrievalLaneIDPattern.MatchString(lane.LaneID) || (index > 0 && lane.LaneID <= previousLaneID) {
			return errors.New("catalog lane IDs must be valid, unique and strictly sorted")
		}
		previousLaneID = lane.LaneID
		if !validSHA256Hex(lane.RetrievalExecutableSHA256) || !validSHA256Hex(lane.RetrievalAdmissionPolicySHA) {
			return fmt.Errorf("lane %q contains an invalid SHA-256 pin", lane.LaneID)
		}
		paths := []struct{ label, value string }{
			{label: "retrieval_executable", value: lane.RetrievalExecutable},
			{label: "retrieval_store", value: lane.RetrievalStore},
			{label: "retrieval_state", value: lane.RetrievalState},
			{label: "retrieval_evidence_store", value: lane.RetrievalEvidenceStore},
			{label: "retrieval_admission_policy", value: lane.RetrievalAdmissionPolicy},
		}
		for _, path := range paths {
			if !validRetrievalString(path.value, 4096, false) || !filepath.IsAbs(path.value) || filepath.Clean(path.value) != path.value {
				return fmt.Errorf("lane %q %s is not a canonical absolute path", lane.LaneID, path.label)
			}
		}
		if owner, duplicate := seenStates[lane.RetrievalState]; duplicate {
			return fmt.Errorf("lanes %q and %q share one signed state root", owner, lane.LaneID)
		}
		seenStates[lane.RetrievalState] = lane.LaneID
	}
	return nil
}

func (provider *retrievalProvider) fuseFederation(outcomes []federationLaneOutcome, limit int, asOf string) toolOutcome {
	accumulators := make(map[string]*federationAccumulator)
	queryTerms := make(map[string]struct{})
	healthy := 0
	degraded := 0
	stateCounts := make(map[typedState]int)
	seenGenerations := make(map[string]string, len(outcomes))

	for index := range outcomes {
		laneOutcome := &outcomes[index]
		if generationID, ok := laneOutcome.outcome.Data["current_generation_id"].(string); ok && generationID != "" {
			if owner, duplicate := seenGenerations[generationID]; duplicate {
				return provider.federationIntegrityFailure(outcomes, limit, asOf, "federation_generation_alias", fmt.Sprintf("lanes %q and %q selected the same signed generation", owner, laneOutcome.lane.LaneID))
			}
			seenGenerations[generationID] = laneOutcome.lane.LaneID
		}
		if laneOutcome.outcome.State != stateOK || laneOutcome.outcome.Error {
			continue
		}
		hits, ok := laneOutcome.outcome.Data["results"].([]currentRetrievalHit)
		if !ok {
			continue
		}
		for _, hit := range hits {
			if hit.Evidence.SourceID != laneOutcome.lane.AdmissionSourceID {
				return provider.federationIntegrityFailure(outcomes, limit, asOf, "federation_source_binding_mismatch", fmt.Sprintf("lane %q returned evidence outside its pinned admission-policy source", laneOutcome.lane.LaneID))
			}
		}
	}

	for index := range outcomes {
		laneOutcome := &outcomes[index]
		if laneOutcome.outcome.State == stateOK && !laneOutcome.outcome.Error {
			if _, ok := laneOutcome.outcome.Data["results"].([]currentRetrievalHit); !ok {
				laneOutcome.outcome = errorOutcome(stateBackendUnavailable, "validated lane returned an internal result type mismatch", map[string]any{"result_state": "backend_unavailable"})
			}
		}
		stateCounts[laneOutcome.outcome.State]++
		if !laneOutcome.outcome.Error && (laneOutcome.outcome.State == stateOK || laneOutcome.outcome.State == stateEmpty) {
			healthy++
		} else {
			degraded++
		}
		terms, _ := laneOutcome.outcome.Data["query_terms"].([]string)
		for _, term := range terms {
			queryTerms[term] = struct{}{}
		}
	}

	for index := range outcomes {
		laneOutcome := &outcomes[index]
		if laneOutcome.outcome.State != stateOK || laneOutcome.outcome.Error {
			continue
		}
		hits := laneOutcome.outcome.Data["results"].([]currentRetrievalHit)
		for rank, sourceHit := range hits {
			fusionScore := limit - rank
			match := federatedRetrievalLaneMatch{LaneID: laneOutcome.lane.LaneID, Rank: rank + 1, SourceScore: sourceHit.Score}
			accumulator, exists := accumulators[sourceHit.Evidence.SpanID]
			if !exists {
				terms := make(map[string]struct{}, len(sourceHit.MatchedTerms))
				for _, term := range sourceHit.MatchedTerms {
					terms[term] = struct{}{}
				}
				accumulators[sourceHit.Evidence.SpanID] = &federationAccumulator{
					hit: federatedRetrievalHit{
						Score: fusionScore, BestLaneRank: rank + 1,
						LaneMatches: []federatedRetrievalLaneMatch{match},
						Evidence:    sourceHit.Evidence, Excerpt: sourceHit.Excerpt, ExcerptTruncated: sourceHit.ExcerptTruncated,
					},
					terms: terms,
				}
				continue
			}
			if !reflect.DeepEqual(accumulator.hit.Evidence, sourceHit.Evidence) || accumulator.hit.Excerpt != sourceHit.Excerpt || accumulator.hit.ExcerptTruncated != sourceHit.ExcerptTruncated {
				return provider.federationIntegrityFailure(outcomes, limit, asOf, "federation_span_conflict", "federated lanes returned conflicting content for one evidence span")
			}
			if fusionScore > accumulator.hit.Score {
				accumulator.hit.Score = fusionScore
			}
			if rank+1 < accumulator.hit.BestLaneRank {
				accumulator.hit.BestLaneRank = rank + 1
			}
			accumulator.hit.LaneMatches = append(accumulator.hit.LaneMatches, match)
			for _, term := range sourceHit.MatchedTerms {
				accumulator.terms[term] = struct{}{}
			}
		}
	}

	results := make([]federatedRetrievalHit, 0, len(accumulators))
	for _, accumulator := range accumulators {
		for term := range accumulator.terms {
			accumulator.hit.MatchedTerms = append(accumulator.hit.MatchedTerms, term)
		}
		sort.Strings(accumulator.hit.MatchedTerms)
		results = append(results, accumulator.hit)
	}
	sort.Slice(results, func(left, right int) bool {
		if results[left].Score != results[right].Score {
			return results[left].Score > results[right].Score
		}
		if results[left].BestLaneRank != results[right].BestLaneRank {
			return results[left].BestLaneRank < results[right].BestLaneRank
		}
		if results[left].LaneMatches[0].LaneID != results[right].LaneMatches[0].LaneID {
			return results[left].LaneMatches[0].LaneID < results[right].LaneMatches[0].LaneID
		}
		if results[left].Evidence.SourceID != results[right].Evidence.SourceID {
			return results[left].Evidence.SourceID < results[right].Evidence.SourceID
		}
		return results[left].Evidence.SpanID < results[right].Evidence.SpanID
	})
	if len(results) > limit {
		results = results[:limit]
	}
	terms := make([]string, 0, len(queryTerms))
	for term := range queryTerms {
		terms = append(terms, term)
	}
	sort.Strings(terms)

	resultState := "ok"
	state := stateOK
	if healthy > 0 && degraded > 0 {
		state, resultState = statePartial, "partial"
	} else if healthy > 0 && len(results) == 0 {
		state, resultState = stateEmpty, "empty"
	} else if healthy == 0 {
		state, resultState = stateBackendUnavailable, "backend_unavailable"
		if stateCounts[stateStale] == len(outcomes) {
			state, resultState = stateStale, "stale"
		} else if stateCounts[stateForbidden] == len(outcomes) {
			state, resultState = stateForbidden, "forbidden"
		}
	}
	data := provider.federationData(outcomes, results, terms, healthy, degraded, limit, asOf, resultState)
	if state == statePartial || state == stateOK || state == stateEmpty {
		return outcome(state, data)
	}
	return errorOutcome(state, "no signed-current retrieval lane can serve this query", data)
}

func (provider *retrievalProvider) federationIntegrityFailure(outcomes []federationLaneOutcome, limit int, asOf, code, message string) toolOutcome {
	data := provider.federationData(outcomes, nil, nil, 0, len(outcomes), limit, asOf, "backend_unavailable")
	data["error_code"] = code
	data["failure_scope"] = "federation"
	return errorOutcome(stateBackendUnavailable, message, data)
}

func (provider *retrievalProvider) federationData(outcomes []federationLaneOutcome, results []federatedRetrievalHit, queryTerms []string, healthy, degraded, limit int, asOf, resultState string) map[string]any {
	if results == nil {
		results = []federatedRetrievalHit{}
	}
	if queryTerms == nil {
		queryTerms = []string{}
	}
	lanes := make([]map[string]any, 0, len(outcomes))
	for _, laneOutcome := range outcomes {
		lanes = append(lanes, federationLaneDescriptor(laneOutcome))
	}
	retrievalState := "federated_current"
	authorityState := "evaluated_current_lanes"
	if healthy == 0 {
		retrievalState, authorityState = "federated_unavailable", "unavailable"
	} else if degraded > 0 {
		retrievalState = "federated_partial"
	}
	return map[string]any{
		"retrieval_state": retrievalState, "result_state": resultState,
		"authority_state": authorityState, "profile": "deterministic_rank_fusion",
		"serving_eligible": healthy > 0, "current_eligible": healthy > 0,
		"catalog_sha256":         "sha256:" + provider.catalogSHA256,
		"catalog_schema_version": "1.0.0", "federation_algorithm": "bounded_borda_v1",
		"fusion_window": limit, "lane_count": len(outcomes), "current_lane_count": healthy,
		"degraded_lane_count": degraded, "lanes": lanes, "query_terms": queryTerms,
		"results": results, "observed_at": asOf, "time_source": "broker_host_clock_utc",
		"principal_scope": "public",
	}
}

func federationLaneDescriptor(laneOutcome federationLaneOutcome) map[string]any {
	values := map[string]any{
		"lane_id":                           laneOutcome.lane.LaneID,
		"admission_source_id":               laneOutcome.lane.AdmissionSourceID,
		"state":                             laneOutcome.outcome.State,
		"retrieval_executable_sha256":       "sha256:" + laneOutcome.lane.RetrievalExecutableSHA256,
		"retrieval_admission_policy_sha256": "sha256:" + laneOutcome.lane.RetrievalAdmissionPolicySHA,
	}
	for _, key := range []string{
		"retrieval_state", "result_state", "authority_state", "profile", "serving_eligible", "current_eligible",
		"pointer_id", "pointer_revision", "transition_receipt_id", "current_generation_id",
		"current_generation_document_sha256", "generation_created_at", "quality_report_id",
		"evaluation_dataset_id", "evaluation_metrics_id", "candidate_manifest_id", "freshness_state", "error_code",
	} {
		if value, exists := laneOutcome.outcome.Data[key]; exists {
			values[key] = value
		}
	}
	if hits, ok := laneOutcome.outcome.Data["results"].([]currentRetrievalHit); ok {
		values["result_count"] = len(hits)
	} else {
		values["result_count"] = 0
	}
	if message, ok := laneOutcome.outcome.Data["message"].(string); ok && message != "" {
		values["message"] = boundedFederationDiagnostic(message)
	}
	return values
}

func boundedFederationDiagnostic(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= maxFederationDiagnosticBytes {
		return value
	}
	end := maxFederationDiagnosticBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end] + " [truncated]"
}
