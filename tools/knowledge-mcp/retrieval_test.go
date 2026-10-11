package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEvidenceSearchUsesBrokerTimeAndPreservesEvaluatedCurrentAuthority(t *testing.T) {
	provider := currentRetrievalFixture(t, currentRetrievalOKResponse(), "2026-07-16T10:34:56Z")
	result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
	if result.Error || result.State != stateOK || result.Data["result_state"] != "ok" {
		t.Fatalf("evaluated-current result contract was not preserved: %#v", result)
	}
	if result.Data["observed_at"] != "2026-07-16T10:34:56Z" || result.Data["time_source"] != "broker_host_clock_utc" {
		t.Fatalf("broker time was not materialized: %#v", result.Data)
	}
	if result.Data["retrieval_state"] != "current" || result.Data["authority_state"] != "evaluated_current" || result.Data["current_eligible"] != true {
		t.Fatalf("signed current authority was not retained: %#v", result.Data)
	}
	if result.Data["pointer_id"] != retrievalID("retrieval-pointer:", "1") || result.Data["current_generation_id"] != retrievalID("retrieval-generation:", "3") || result.Data["evaluation_dataset_id"] != retrievalID("retrieval-evaluation-suite:", "6") {
		t.Fatalf("pointer/generation/evaluation lineage was lost: %#v", result.Data)
	}
	hits, ok := result.Data["results"].([]currentRetrievalHit)
	if !ok || len(hits) != 1 || hits[0].Evidence.SpanID != retrievalID("evidence-span:", "a") || hits[0].Evidence.RawLineStart != 8 || hits[0].Evidence.RawLineEnd != 11 {
		t.Fatalf("exact citation was not preserved: %#v", result.Data["results"])
	}
}

func TestRetrievalCommandExecutesTheOpenedPinnedInode(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "retrieval")
	original := []byte("#!/bin/sh\nprintf 'opened-pinned-inode\\n'\n")
	if err := os.WriteFile(executable, original, 0o555); err != nil {
		t.Fatal(err)
	}
	digest, _, err := hashBoundFile(executable, maxRetrievalExecutableBytes)
	if err != nil {
		t.Fatal(err)
	}
	provider := &retrievalProvider{executable: executable, executableSHA256: strings.TrimPrefix(digest, "sha256:")}
	opened, err := provider.openValidatedExecutable()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	saved := executable + ".saved"
	if err := os.Rename(executable, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf 'path-replacement\\n'\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	command := provider.retrievalCommand(ctx, opened, nil)
	if command.SysProcAttr == nil || !command.SysProcAttr.Setpgid || command.Cancel == nil || command.WaitDelay != 100*time.Millisecond {
		t.Fatalf("retrieval command lost bounded process-group cancellation: %#v", command)
	}
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "opened-pinned-inode\n" {
		t.Fatalf("command executed the replaced path instead of the pinned descriptor: %q", output)
	}
	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, executable); err != nil {
		t.Fatal(err)
	}
	if err := provider.validateOpenedExecutable(opened); err != nil {
		t.Fatalf("restored path no longer binds the actually executed inode: %v", err)
	}
}

func TestRetrievalFederationDeadlineBudgetIsFixedAndBelowMCPBoundary(t *testing.T) {
	if retrievalFederationLaneTimeout != 20*time.Second {
		t.Fatalf("federation lane deadline is not the reviewed fixed budget: %s", retrievalFederationLaneTimeout)
	}
	if retrievalFederationWaveCount != 2 {
		t.Fatalf("maximum catalog no longer drains in exactly two bounded waves: %d", retrievalFederationWaveCount)
	}
	if retrievalFederationChildBudget != 40*time.Second {
		t.Fatalf("maximum child-process schedule is not the reviewed 40-second budget: %s", retrievalFederationChildBudget)
	}
	if retrievalFederationChildBudget >= retrievalFederationMCPBudget {
		t.Fatalf("child-process schedule %s leaves no MCP overhead inside %s", retrievalFederationChildBudget, retrievalFederationMCPBudget)
	}
}

func TestEvidenceSearchRejectsCallerTimeOverride(t *testing.T) {
	provider := &retrievalProvider{now: func() time.Time { return time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC) }}
	result := provider.search(context.Background(), map[string]json.RawMessage{
		"query": json.RawMessage(`"argo"`),
		"as_of": json.RawMessage(`"2026-07-15T00:00:00Z"`),
	})
	if !result.Error || result.State != stateForbidden || !strings.Contains(result.Data["message"].(string), "unknown argument") {
		t.Fatalf("caller-controlled freshness time was accepted: %#v", result)
	}
	for _, definition := range (&toolService{}).definitions() {
		if definition.Name != "evidence_search" {
			continue
		}
		properties := definition.InputSchema["properties"].(map[string]any)
		if _, exists := properties["as_of"]; exists {
			t.Fatal("evidence_search schema exposes caller-controlled as_of")
		}
		return
	}
	t.Fatal("evidence_search tool definition missing")
}

func TestEvidenceSearchRejectsCallerLaneSelection(t *testing.T) {
	provider := &retrievalProvider{now: func() time.Time { return time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC) }}
	result := provider.search(context.Background(), map[string]json.RawMessage{
		"query": json.RawMessage(`"argo"`),
		"lane":  json.RawMessage(`"alpha"`),
	})
	if !result.Error || result.State != stateForbidden || !strings.Contains(result.Data["message"].(string), "unknown argument") {
		t.Fatalf("caller-controlled lane selection was accepted: %#v", result)
	}
	for _, definition := range (&toolService{}).definitions() {
		if definition.Name != "evidence_search" {
			continue
		}
		if _, exists := definition.InputSchema["properties"].(map[string]any)["lane"]; exists {
			t.Fatal("evidence_search schema exposes caller-controlled lane selection")
		}
		return
	}
	t.Fatal("evidence_search tool definition missing")
}

func TestEvidenceSearchRejectsCallerTimeoutOverride(t *testing.T) {
	provider := &retrievalProvider{now: func() time.Time { return time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC) }}
	result := provider.search(context.Background(), map[string]json.RawMessage{
		"query":           json.RawMessage(`"argo"`),
		"timeout_seconds": json.RawMessage(`59`),
	})
	if !result.Error || result.State != stateForbidden || !strings.Contains(result.Data["message"].(string), "unknown argument") {
		t.Fatalf("caller-controlled retrieval timeout was accepted: %#v", result)
	}
	for _, definition := range (&toolService{}).definitions() {
		if definition.Name != "evidence_search" {
			continue
		}
		if _, exists := definition.InputSchema["properties"].(map[string]any)["timeout_seconds"]; exists {
			t.Fatal("evidence_search schema exposes caller-controlled timeout")
		}
		return
	}
	t.Fatal("evidence_search tool definition missing")
}

func TestEvidenceSearchFailsClosedWithoutCompleteConfiguration(t *testing.T) {
	provider := &retrievalProvider{now: func() time.Time { return time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC) }}
	result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"argo"`)})
	if !result.Error || result.State != stateBackendUnavailable || result.Data["observed_at"] != "2026-07-16T10:00:00Z" {
		t.Fatalf("unconfigured provider did not fail closed: %#v", result)
	}
}

func TestEvidenceSearchDoesNotFallBackWhenCurrentPointerIsMissing(t *testing.T) {
	response := `{"state":"backend_unavailable","result_state":"backend_unavailable","authority_state":"unavailable","profile":"lexical","serving_eligible":false,"current_eligible":false,"results":[],"error_code":"pointer-missing"}`
	provider := currentRetrievalFixture(t, response, "2026-07-16T10:34:56Z")
	result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
	if !result.Error || result.State != stateBackendUnavailable || result.Data["retrieval_state"] != "backend_unavailable" || result.Data["error_code"] != "pointer-missing" {
		t.Fatalf("missing current pointer did not fail closed: %#v", result)
	}
	if hits := result.Data["results"].([]currentRetrievalHit); len(hits) != 0 {
		t.Fatalf("missing current pointer returned fallback evidence: %#v", hits)
	}
}

func TestEvidenceSearchRejectsCandidateOrMalformedCitationResponses(t *testing.T) {
	t.Run("candidate response", func(t *testing.T) {
		response := `{"state":"partial","result_state":"ok","promotable":false,"lexical":true,"dense":false,"results":[]}`
		provider := currentRetrievalFixture(t, response, "2026-07-16T10:34:56Z")
		result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
		if !result.Error || result.State != stateBackendUnavailable || !strings.Contains(result.Data["message"].(string), "invalid JSON") {
			t.Fatalf("candidate response was accepted by promoted mode: %#v", result)
		}
	})

	t.Run("malformed citation", func(t *testing.T) {
		response := strings.Replace(currentRetrievalOKResponse(), `"raw_sha256":"sha256:`+strings.Repeat("b", 64)+`"`, `"raw_sha256":"bad"`, 1)
		provider := currentRetrievalFixture(t, response, "2026-07-16T10:34:56Z")
		result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
		if !result.Error || result.State != stateBackendUnavailable || !strings.Contains(result.Data["message"].(string), "citation content identity") {
			t.Fatalf("malformed citation was accepted: %#v", result)
		}
	})
}

func TestEvidenceSearchRequiresCoherentCitationCoordinates(t *testing.T) {
	const coordinates = `"payload_byte_size":256,"raw_byte_start":100,"raw_byte_end":356,"raw_line_start":8,"raw_line_end":11,`
	for _, testCase := range []struct {
		name     string
		replaced string
		rejected string
	}{
		{"exact raw slice", `"payload_byte_size":256,"raw_byte_start":100,"raw_byte_end":356,"raw_line_start":8,"raw_line_end":11,`, ""},
		{"single byte single line", `"payload_byte_size":1,"raw_byte_start":0,"raw_byte_end":1,"raw_line_start":1,"raw_line_end":1,`, ""},
		{"one byte per line boundary", `"payload_byte_size":3,"raw_byte_start":0,"raw_byte_end":3,"raw_line_start":1,"raw_line_end":4,`, ""},
		{"payload shorter than span", `"payload_byte_size":200,"raw_byte_start":100,"raw_byte_end":356,"raw_line_start":8,"raw_line_end":11,`, "payload size does not match its raw byte span"},
		{"payload longer than span", `"payload_byte_size":512,"raw_byte_start":100,"raw_byte_end":356,"raw_line_start":8,"raw_line_end":11,`, "payload size does not match its raw byte span"},
		{"line span exceeds payload bytes", `"payload_byte_size":2,"raw_byte_start":100,"raw_byte_end":102,"raw_line_start":8,"raw_line_end":11,`, "line span cannot fit its payload bytes"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := strings.Replace(currentRetrievalOKResponse(), coordinates, testCase.replaced, 1)
			if !strings.Contains(response, testCase.replaced) {
				t.Fatal("citation coordinate fixture did not substitute")
			}
			provider := currentRetrievalFixture(t, response, "2026-07-16T10:34:56Z")
			result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
			if testCase.rejected == "" {
				if result.Error || result.State != stateOK {
					t.Fatalf("coherent citation coordinates were rejected: %#v", result)
				}
				return
			}
			if !result.Error || result.State != stateBackendUnavailable || !strings.Contains(result.Data["message"].(string), testCase.rejected) {
				t.Fatalf("incoherent citation coordinates were accepted: %#v", result)
			}
		})
	}
}

func TestRetrievalConfigMustBeAllOrNothing(t *testing.T) {
	root := t.TempDir()
	_, err := loadConfig([]string{"--repository-root", root, "--retrieval-executable", "/tmp/retrieval"}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "requires executable") {
		t.Fatalf("partial retrieval configuration was accepted: %v", err)
	}
}

func TestRetrievalConfigRequiresSignedCurrentStateAndValidPins(t *testing.T) {
	root := t.TempDir()
	arguments := completeRetrievalArguments(root)
	configuration, err := loadConfig(arguments, func(string) string { return "" })
	if err != nil || configuration.retrievalState != "/tmp/state" || configuration.retrievalExecutableHash != strings.Repeat("a", 64) {
		t.Fatalf("complete signed-current retrieval configuration was rejected: %#v, %v", configuration, err)
	}
	arguments[len(arguments)-1] = "BAD"
	if _, err := loadConfig(arguments, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "64 lowercase hexadecimal") {
		t.Fatalf("invalid admission-policy pin was accepted: %v", err)
	}
}

func TestRetrievalConfigRejectsLegacyCandidateSelection(t *testing.T) {
	root := t.TempDir()
	environment := map[string]string{"ARCHEION_RETRIEVAL_CANDIDATE": "/tmp/candidate"}
	_, err := loadConfig([]string{"--repository-root", root}, func(key string) string { return environment[key] })
	if err == nil || !strings.Contains(err.Error(), "direct retrieval candidate configuration is unsupported") {
		t.Fatalf("legacy candidate environment was not rejected: %v", err)
	}
}

func TestRetrievalFederationConfigIsHashPinnedAndMutuallyExclusive(t *testing.T) {
	root := t.TempDir()
	arguments := []string{
		"--repository-root", root,
		"--retrieval-catalog", "/tmp/retrieval-catalog.json",
		"--retrieval-catalog-sha256", strings.Repeat("d", 64),
	}
	configuration, err := loadConfig(arguments, func(string) string { return "" })
	if err != nil || configuration.retrievalCatalog != "/tmp/retrieval-catalog.json" || configuration.retrievalCatalogHash != strings.Repeat("d", 64) {
		t.Fatalf("complete federation configuration was rejected: %#v, %v", configuration, err)
	}
	if _, err := loadConfig(arguments[:len(arguments)-2], func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "catalog and catalog SHA-256") {
		t.Fatalf("unpaired catalog configuration was accepted: %v", err)
	}
	if _, err := loadConfig(append(arguments, completeRetrievalArguments(root)[2:]...), func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("catalog and legacy single lane were accepted together: %v", err)
	}
}

func TestEvidenceSearchFederatesIndependentSignedCurrentLanesDeterministically(t *testing.T) {
	provider, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
		{laneID: "alpha", state: "/state-alpha", response: currentRetrievalOKResponseFor("alpha", "a")},
		{laneID: "beta", state: "/state-beta", response: currentRetrievalOKResponseFor("beta", "b")},
	}, "2026-07-16T11:00:00Z")
	result := provider.search(context.Background(), map[string]json.RawMessage{
		"query": json.RawMessage(`"sync"`), "limit": json.RawMessage(`2`),
	})
	if result.Error || result.State != stateOK || result.Data["result_state"] != "ok" || result.Data["retrieval_state"] != "federated_current" {
		t.Fatalf("healthy federation did not serve: %#v", result)
	}
	if result.Data["lane_count"] != 2 || result.Data["current_lane_count"] != 2 || result.Data["degraded_lane_count"] != 0 || result.Data["federation_algorithm"] != "bounded_borda_v1" {
		t.Fatalf("federation bounds/health metadata is wrong: %#v", result.Data)
	}
	hits, ok := result.Data["results"].([]federatedRetrievalHit)
	if !ok || len(hits) != 2 || hits[0].Score != 2 || hits[1].Score != 2 || hits[0].LaneMatches[0].LaneID != "alpha" || hits[1].LaneMatches[0].LaneID != "beta" {
		t.Fatalf("rank fusion was not deterministic: %#v", result.Data["results"])
	}
	if hits[0].Evidence.SpanID != retrievalID("evidence-span:", "a") || hits[1].Evidence.SpanID != retrievalID("evidence-span:", "b") || hits[1].Evidence.SourceID != "src:github:argoproj/argo-workflows@v3.4.5:docs" {
		t.Fatalf("federation lost exact per-source citations: %#v", hits)
	}
	lanes := result.Data["lanes"].([]map[string]any)
	if lanes[0]["admission_source_id"] == lanes[1]["admission_source_id"] || lanes[0]["current_generation_id"] == lanes[1]["current_generation_id"] || lanes[0]["pointer_id"] == lanes[1]["pointer_id"] {
		t.Fatalf("independent signed-current lineages were collapsed: %#v", lanes)
	}
}

func TestEvidenceSearchFederationReturnsUsefulTypedPartialState(t *testing.T) {
	provider, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
		{laneID: "alpha", state: "/state-alpha", response: currentRetrievalOKResponseFor("alpha", "a")},
		{laneID: "beta", state: "/state-beta", response: currentRetrievalBackendUnavailableResponse("pointer-missing")},
	}, "2026-07-16T11:00:00Z")
	result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
	if result.Error || result.State != statePartial || result.Data["result_state"] != "partial" || result.Data["retrieval_state"] != "federated_partial" {
		t.Fatalf("one failed lane did not produce a usable typed partial result: %#v", result)
	}
	if result.Data["current_lane_count"] != 1 || result.Data["degraded_lane_count"] != 1 {
		t.Fatalf("partial lane counts are wrong: %#v", result.Data)
	}
	hits := result.Data["results"].([]federatedRetrievalHit)
	lanes := result.Data["lanes"].([]map[string]any)
	if len(hits) != 1 || lanes[1]["state"] != stateBackendUnavailable || lanes[1]["error_code"] != "pointer-missing" {
		t.Fatalf("partial result hid evidence or failure lineage: %#v", result.Data)
	}
}

func TestEvidenceSearchFederationFailsClosedWhenNoLaneCanServe(t *testing.T) {
	provider, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
		{laneID: "alpha", state: "/state-alpha", response: currentRetrievalBackendUnavailableResponse("pointer-missing")},
		{laneID: "beta", state: "/state-beta", response: currentRetrievalBackendUnavailableResponse("state-raced")},
	}, "2026-07-16T11:00:00Z")
	result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
	if !result.Error || result.State != stateBackendUnavailable || result.Data["result_state"] != "backend_unavailable" || len(result.Data["results"].([]federatedRetrievalHit)) != 0 {
		t.Fatalf("unavailable federation did not fail closed: %#v", result)
	}
	assertFederationUnavailableAuthority(t, result)
}

func TestEvidenceSearchFederationPreservesUniformStaleAndForbiddenStates(t *testing.T) {
	for _, test := range []struct {
		name  string
		state typedState
	}{
		{name: "stale", state: stateStale},
		{name: "forbidden", state: stateForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
				{laneID: "alpha", state: "/state-alpha", response: currentRetrievalNonServingResponse(t, test.name, "a")},
				{laneID: "beta", state: "/state-beta", response: currentRetrievalNonServingResponse(t, test.name, "b")},
			}, "2026-07-16T11:00:00Z")
			result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
			if !result.Error || result.State != test.state || result.Data["result_state"] != test.name || len(result.Data["results"].([]federatedRetrievalHit)) != 0 {
				t.Fatalf("uniform %s lanes lost their typed state: %#v", test.name, result)
			}
		})
	}
}

func TestEvidenceSearchFederationRejectsAliasInflationAndSpanConflicts(t *testing.T) {
	alpha := currentRetrievalOKResponseFor("alpha", "a")
	beta := currentRetrievalOKResponseFor("beta", "b")

	t.Run("same pinned source policy", func(t *testing.T) {
		provider, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
			{laneID: "alpha", state: "/state-alpha", response: alpha},
			{laneID: "beta", state: "/state-beta", response: alpha},
		}, "2026-07-16T11:00:00Z")
		result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`), "limit": json.RawMessage(`2`)})
		assertFederationUnavailableAuthority(t, result)
		if result.Data["error_code"] != "federation_catalog_invalid" || !strings.Contains(result.Data["message"].(string), "same admission-policy source_id") {
			t.Fatalf("source-policy alias was not rejected: %#v", result)
		}
	})

	t.Run("same signed generation", func(t *testing.T) {
		aliasedGeneration := strings.Replace(beta, retrievalID("retrieval-generation:", "b"), retrievalID("retrieval-generation:", "a"), 1)
		provider, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
			{laneID: "alpha", state: "/state-alpha", response: alpha},
			{laneID: "beta", state: "/state-beta", response: aliasedGeneration},
		}, "2026-07-16T11:00:00Z")
		result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`), "limit": json.RawMessage(`2`)})
		assertFederationUnavailableAuthority(t, result)
		if result.Data["error_code"] != "federation_generation_alias" {
			t.Fatalf("signed-generation alias was not rejected: %#v", result)
		}
	})

	t.Run("response outside pinned source policy", func(t *testing.T) {
		provider, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
			{laneID: "alpha", state: "/state-alpha", response: alpha},
			{laneID: "beta", state: "/state-beta", response: beta, admissionSourceID: "src:test:not-beta"},
		}, "2026-07-16T11:00:00Z")
		result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`), "limit": json.RawMessage(`2`)})
		assertFederationUnavailableAuthority(t, result)
		if result.Data["error_code"] != "federation_source_binding_mismatch" {
			t.Fatalf("out-of-policy source evidence was not rejected: %#v", result)
		}
	})

	t.Run("conflicting span identity", func(t *testing.T) {
		conflict := strings.Replace(beta, retrievalID("evidence-span:", "b"), retrievalID("evidence-span:", "a"), 1)
		provider, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
			{laneID: "alpha", state: "/state-alpha", response: alpha},
			{laneID: "beta", state: "/state-beta", response: conflict},
		}, "2026-07-16T11:00:00Z")
		result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`), "limit": json.RawMessage(`2`)})
		assertFederationUnavailableAuthority(t, result)
		if result.Data["error_code"] != "federation_span_conflict" || !strings.Contains(result.Data["message"].(string), "conflicting content") {
			t.Fatalf("one span ID with conflicting bytes was accepted: %#v", result)
		}
		first, _ := json.Marshal(result.Data)
		secondResult := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`), "limit": json.RawMessage(`2`)})
		second, _ := json.Marshal(secondResult.Data)
		if !bytes.Equal(first, second) {
			t.Fatalf("federation integrity failure was nondeterministic:\n%s\n%s", first, second)
		}
	})
}

func TestEvidenceSearchFederationRejectsCatalogTamperAndAmbiguousLanes(t *testing.T) {
	provider, catalogPath := currentRetrievalFederationFixture(t, []federationFixtureLane{
		{laneID: "alpha", state: "/state-alpha", response: currentRetrievalOKResponseFor("alpha", "a")},
	}, "2026-07-16T11:00:00Z")
	if err := os.Chmod(catalogPath, 0o644); err != nil {
		t.Fatal(err)
	}
	result := provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
	assertFederationUnavailableAuthority(t, result)
	if !result.Error || result.State != stateBackendUnavailable || !strings.Contains(result.Data["message"].(string), "immutable regular file") {
		t.Fatalf("writable federation catalog was accepted: %#v", result)
	}
	if err := os.WriteFile(catalogPath, append(mustReadFile(t, catalogPath), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(catalogPath, 0o444); err != nil {
		t.Fatal(err)
	}
	result = provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
	assertFederationUnavailableAuthority(t, result)
	if !result.Error || result.State != stateBackendUnavailable || !strings.Contains(result.Data["message"].(string), "SHA-256") {
		t.Fatalf("catalog hash tamper was accepted: %#v", result)
	}
	trimmed := bytes.TrimSpace(mustReadFile(t, catalogPath))
	duplicateKeyCatalog := append(append([]byte(nil), trimmed[:len(trimmed)-1]...), []byte(`,"record_kind":"retrieval_federation_catalog"}`)...)
	if err := os.Chmod(catalogPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, duplicateKeyCatalog, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(catalogPath, 0o444); err != nil {
		t.Fatal(err)
	}
	duplicateDigest, _, err := hashBoundFile(catalogPath, maxRetrievalCatalogBytes)
	if err != nil {
		t.Fatal(err)
	}
	provider.catalogSHA256 = strings.TrimPrefix(duplicateDigest, "sha256:")
	result = provider.search(context.Background(), map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)})
	assertFederationUnavailableAuthority(t, result)
	if !result.Error || result.State != stateBackendUnavailable || !strings.Contains(result.Data["message"].(string), "duplicate JSON object key") {
		t.Fatalf("duplicate-key but correctly pinned catalog was accepted: %#v", result)
	}

	lane := retrievalFederationLane{
		LaneID: "beta", RetrievalExecutable: "/bin/tool", RetrievalExecutableSHA256: strings.Repeat("a", 64),
		RetrievalStore: "/store-beta", RetrievalState: "/shared-state", RetrievalEvidenceStore: "/evidence-beta",
		RetrievalAdmissionPolicy: "/policy-beta", RetrievalAdmissionPolicySHA: strings.Repeat("b", 64),
	}
	other := lane
	other.LaneID = "alpha"
	if err := validateRetrievalFederationCatalog(retrievalFederationCatalog{SchemaVersion: "1.0.0", RecordKind: "retrieval_federation_catalog", Lanes: []retrievalFederationLane{lane, other}}); err == nil || !strings.Contains(err.Error(), "strictly sorted") {
		t.Fatalf("unsorted catalog was accepted: %v", err)
	}
	other.LaneID = "gamma"
	if err := validateRetrievalFederationCatalog(retrievalFederationCatalog{SchemaVersion: "1.0.0", RecordKind: "retrieval_federation_catalog", Lanes: []retrievalFederationLane{lane, other}}); err == nil || !strings.Contains(err.Error(), "share one signed state root") {
		t.Fatalf("duplicate signed state root was accepted: %v", err)
	}

	var decoded retrievalFederationCatalog
	unknown := `{"schema_version":"1.0.0","record_kind":"retrieval_federation_catalog","lanes":[],"unknown":true}`
	if err := decodeStrictTyped([]byte(unknown), &decoded); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown catalog field was accepted: %v", err)
	}
	tooMany := retrievalFederationCatalog{SchemaVersion: "1.0.0", RecordKind: "retrieval_federation_catalog"}
	for index := 0; index <= maxRetrievalFederationLanes; index++ {
		candidate := lane
		candidate.LaneID = fmt.Sprintf("lane-%02d", index)
		candidate.RetrievalState = fmt.Sprintf("/state-%02d", index)
		tooMany.Lanes = append(tooMany.Lanes, candidate)
	}
	if err := validateRetrievalFederationCatalog(tooMany); err == nil || !strings.Contains(err.Error(), "between 1 and") {
		t.Fatalf("unbounded federation catalog was accepted: %v", err)
	}
}

func completeRetrievalArguments(root string) []string {
	return []string{
		"--repository-root", root,
		"--retrieval-executable", "/tmp/retrieval",
		"--retrieval-executable-sha256", strings.Repeat("a", 64),
		"--retrieval-store", "/tmp/store",
		"--retrieval-state", "/tmp/state",
		"--retrieval-evidence-store", "/tmp/evidence",
		"--retrieval-admission-policy", "/tmp/policy",
		"--retrieval-admission-policy-sha256", strings.Repeat("c", 64),
	}
}

type federationFixtureLane struct {
	laneID            string
	state             string
	response          string
	admissionSourceID string
}

func currentRetrievalFederationFixture(t *testing.T, fixtureLanes []federationFixtureLane, expectedAsOf string) (*retrievalProvider, string) {
	t.Helper()
	sort.Slice(fixtureLanes, func(left, right int) bool { return fixtureLanes[left].laneID < fixtureLanes[right].laneID })
	directory := t.TempDir()
	executable := filepath.Join(directory, "retrieval")
	type fixturePolicy struct{ path, hash, sourceID string }
	policies := make([]fixturePolicy, len(fixtureLanes))
	for index, lane := range fixtureLanes {
		sourceID := lane.admissionSourceID
		if sourceID == "" {
			var response currentRetrievalResponse
			if err := json.Unmarshal([]byte(lane.response), &response); err == nil && len(response.Results) > 0 {
				sourceID = response.Results[0].Evidence.SourceID
			} else {
				sourceID = "src:test:" + lane.laneID
			}
		}
		identityDigit := string("cdef0123"[index])
		payloadDigest := "sha256:" + strings.Repeat(identityDigit, 64)
		policy := retrievalAdmissionIdentity{
			PolicyID: "retrieval-admission:" + payloadDigest, PolicyPayloadSHA256: payloadDigest,
			SchemaVersion: "1.0.0", PolicyKind: "public_retrieval_admission", State: "active",
			SnapshotManifestID: retrievalID("snapshot-manifest:", identityDigit),
			EvidenceManifestID: retrievalID("evidence-manifest:", identityDigit),
			SnapshotID:         "snp:test:" + lane.laneID, SourceID: sourceID,
			ComponentID: "cmp:test:" + lane.laneID, ComponentVersionID: "ver:test:" + lane.laneID + "@1",
			AccessScope: "public", RetrievalAllowed: true, SourceState: "present", DeletionState: "active",
			EvaluatedAt: "2026-07-16T09:00:00Z", FreshUntil: "2026-07-17T09:00:00Z",
		}
		policyBytes, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		policyPath := filepath.Join(directory, "policy-"+lane.laneID+".json")
		if err := os.WriteFile(policyPath, policyBytes, 0o444); err != nil {
			t.Fatal(err)
		}
		policyDigest, _, err := hashBoundFile(policyPath, maxRetrievalAdmissionBytes)
		if err != nil {
			t.Fatal(err)
		}
		policies[index] = fixturePolicy{path: policyPath, hash: strings.TrimPrefix(policyDigest, "sha256:"), sourceID: sourceID}
	}
	var cases strings.Builder
	for index, lane := range fixtureLanes {
		if strings.Contains(lane.response, "'") {
			t.Fatal("test response cannot be safely single-quoted by the shell fixture")
		}
		fmt.Fprintf(&cases, "  %s) [ \"$store\" = \"/store-%s\" ] && [ \"$evidence\" = \"/evidence-%s\" ] && [ \"$policy\" = \"%s\" ] && [ \"$policy_sha\" = \"sha256:%s\" ] || exit 14; printf '%%s\\n' '%s' ;;\n", lane.state, lane.laneID, lane.laneID, policies[index].path, policies[index].hash, lane.response)
	}
	script := "#!/bin/sh\n" +
		"[ \"$1\" = \"current-query\" ] || exit 9\n" +
		"[ \"$PATH\" = \"/usr/bin:/bin\" ] || exit 13\n" +
		"shift\nstate=\nas_of=\nstore=\nevidence=\npolicy=\npolicy_sha=\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  case \"$1\" in\n" +
		"    --state) shift; state=$1 ;;\n" +
		"    --as-of) shift; as_of=$1 ;;\n" +
		"    --store) shift; store=$1 ;;\n" +
		"    --evidence-store) shift; evidence=$1 ;;\n" +
		"    --admission-policy) shift; policy=$1 ;;\n" +
		"    --admission-policy-sha256) shift; policy_sha=$1 ;;\n" +
		"    --candidate|--candidate-sha256) exit 12 ;;\n" +
		"  esac\n" +
		"  shift\n" +
		"done\n" +
		"[ \"$as_of\" = \"" + expectedAsOf + "\" ] || exit 11\n" +
		"case \"$state\" in\n" + cases.String() + "  *) exit 10 ;;\nesac\n"
	if err := os.WriteFile(executable, []byte(script), 0o555); err != nil {
		t.Fatal(err)
	}
	executableDigest, _, err := hashBoundFile(executable, maxRetrievalExecutableBytes)
	if err != nil {
		t.Fatal(err)
	}
	catalog := retrievalFederationCatalog{SchemaVersion: "1.0.0", RecordKind: "retrieval_federation_catalog"}
	for index, lane := range fixtureLanes {
		catalog.Lanes = append(catalog.Lanes, retrievalFederationLane{
			LaneID: lane.laneID, RetrievalExecutable: executable,
			RetrievalExecutableSHA256: strings.TrimPrefix(executableDigest, "sha256:"),
			RetrievalStore:            "/store-" + lane.laneID, RetrievalState: lane.state,
			RetrievalEvidenceStore:      "/evidence-" + lane.laneID,
			RetrievalAdmissionPolicy:    policies[index].path,
			RetrievalAdmissionPolicySHA: policies[index].hash,
		})
	}
	catalogBytes, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(directory, "retrieval-catalog.json")
	if err := os.WriteFile(catalogPath, catalogBytes, 0o444); err != nil {
		t.Fatal(err)
	}
	catalogDigest, _, err := hashBoundFile(catalogPath, maxRetrievalCatalogBytes)
	if err != nil {
		t.Fatal(err)
	}
	parsedNow, err := time.Parse("2006-01-02T15:04:05Z", expectedAsOf)
	if err != nil {
		t.Fatal(err)
	}
	return &retrievalProvider{
		configured: true, catalog: catalogPath, catalogSHA256: strings.TrimPrefix(catalogDigest, "sha256:"),
		now: func() time.Time { return parsedNow },
	}, catalogPath
}

func currentRetrievalOKResponseFor(laneID, digestDigit string) string {
	response := currentRetrievalLineageResponse(currentRetrievalOKResponse(), digestDigit)
	response = strings.Replace(response, retrievalID("evidence-span:", "a"), retrievalID("evidence-span:", digestDigit), 1)
	if laneID == "beta" {
		response = strings.ReplaceAll(response, "argoproj/argo-cd", "argoproj/argo-workflows")
		response = strings.Replace(response, `"excerpt":"sync waves"`, `"excerpt":"sync hooks"`, 1)
	}
	return response
}

func currentRetrievalLineageResponse(response, digestDigit string) string {
	for _, prefix := range []string{
		"retrieval-pointer:", "retrieval-receipt:", "retrieval-generation:", "retrieval-quality-report:",
		"retrieval-evaluation-suite:", "retrieval-evaluation-metrics:", "retrieval-candidate:",
	} {
		for _, originalDigit := range []string{"1", "2", "3", "5", "6", "7", "8"} {
			original := retrievalID(prefix, originalDigit)
			if strings.Contains(response, original) {
				response = strings.Replace(response, original, retrievalID(prefix, digestDigit), 1)
				break
			}
		}
	}
	return response
}

func currentRetrievalBackendUnavailableResponse(code string) string {
	return `{"state":"backend_unavailable","result_state":"backend_unavailable","authority_state":"unavailable","profile":"lexical","serving_eligible":false,"current_eligible":false,"results":[],"error_code":"` + code + `"}`
}

func currentRetrievalNonServingResponse(t *testing.T, resultState, digestDigit string) string {
	t.Helper()
	var response currentRetrievalResponse
	if err := json.Unmarshal([]byte(currentRetrievalLineageResponse(currentRetrievalOKResponse(), digestDigit)), &response); err != nil {
		t.Fatal(err)
	}
	response.ResultState = resultState
	response.Results = []currentRetrievalHit{}
	if resultState == "stale" {
		response.ServingEligible = false
		response.FreshnessState = "stale"
	} else {
		response.ErrorCode = "query-forbidden"
	}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertFederationUnavailableAuthority(t *testing.T, result toolOutcome) {
	t.Helper()
	if !result.Error || result.State != stateBackendUnavailable ||
		result.Data["retrieval_state"] != "federated_unavailable" || result.Data["authority_state"] != "unavailable" ||
		result.Data["serving_eligible"] != false || result.Data["current_eligible"] != false ||
		result.Data["current_lane_count"] != 0 {
		t.Fatalf("federation-wide failure overstated authority: %#v", result)
	}
	hits, ok := result.Data["results"].([]federatedRetrievalHit)
	if !ok || len(hits) != 0 {
		t.Fatalf("federation-wide failure returned evidence: %#v", result.Data["results"])
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func currentRetrievalFixture(t *testing.T, response, expectedAsOf string) *retrievalProvider {
	t.Helper()
	directory := t.TempDir()
	executable := filepath.Join(directory, "retrieval")
	if strings.Contains(response, "'") {
		t.Fatal("test response cannot be safely single-quoted by the shell fixture")
	}
	script := "#!/bin/sh\n" +
		"[ \"$1\" = \"current-query\" ] || exit 9\n" +
		"[ \"$PATH\" = \"/usr/bin:/bin\" ] || exit 13\n" +
		"shift\nstate=\nas_of=\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  case \"$1\" in\n" +
		"    --state) shift; state=$1 ;;\n" +
		"    --as-of) shift; as_of=$1 ;;\n" +
		"    --candidate|--candidate-sha256) exit 12 ;;\n" +
		"  esac\n" +
		"  shift\n" +
		"done\n" +
		"[ \"$state\" = \"/state\" ] || exit 10\n" +
		"[ \"$as_of\" = \"" + expectedAsOf + "\" ] || exit 11\n" +
		"printf '%s\\n' '" + response + "'\n"
	if err := os.WriteFile(executable, []byte(script), 0o555); err != nil {
		t.Fatal(err)
	}
	digest, _, err := hashBoundFile(executable, maxRetrievalExecutableBytes)
	if err != nil {
		t.Fatal(err)
	}
	return &retrievalProvider{
		configured: true, executable: executable, executableSHA256: strings.TrimPrefix(digest, "sha256:"),
		store: "/store", state: "/state", evidenceStore: "/evidence", admissionPolicy: "/policy",
		admissionPolicyHash: strings.Repeat("c", 64),
		now: func() time.Time {
			parsed, parseErr := time.Parse("2006-01-02T15:04:05Z", expectedAsOf)
			if parseErr != nil {
				panic(parseErr)
			}
			return parsed
		},
	}
}

func currentRetrievalOKResponse() string {
	return `{"state":"current","result_state":"ok","authority_state":"evaluated_current","profile":"lexical","serving_eligible":true,"current_eligible":true,` +
		`"pointer_id":"` + retrievalID("retrieval-pointer:", "1") + `","pointer_revision":7,"transition_receipt_id":"` + retrievalID("retrieval-receipt:", "2") + `",` +
		`"current_generation_id":"` + retrievalID("retrieval-generation:", "3") + `","current_generation_document_sha256":"sha256:` + strings.Repeat("4", 64) + `",` +
		`"generation_created_at":"2026-07-16T09:00:00Z","quality_report_id":"` + retrievalID("retrieval-quality-report:", "5") + `",` +
		`"evaluation_dataset_id":"` + retrievalID("retrieval-evaluation-suite:", "6") + `","evaluation_metrics_id":"` + retrievalID("retrieval-evaluation-metrics:", "7") + `",` +
		`"candidate_manifest_id":"` + retrievalID("retrieval-candidate:", "8") + `","freshness_state":"fresh","query_terms":["sync"],"results":[{` +
		`"score":3,"matched_terms":["sync"],"evidence":{"span_id":"` + retrievalID("evidence-span:", "a") + `","occurrence_id":"` + retrievalID("evidence-occurrence:", "9") + `",` +
		`"source_id":"src:github:argoproj/argo-cd@v3.4.5:docs","component_id":"cmp:github:argoproj/argo-cd","component_version_id":"ver:github:argoproj/argo-cd@v3.4.5","channel_id":"chn:argocd:source",` +
		`"canonical_source_uri":"https://github.com/argoproj/argo-cd/blob/v3.4.5/docs/operator-manual/health.md","canonical_snapshot_uri":"urn:archeion:snapshot:argo:v3.4.5",` +
		`"snapshot_manifest_id":"` + retrievalID("snapshot-manifest:", "d") + `","evidence_manifest_id":"` + retrievalID("evidence-manifest:", "e") + `","snapshot_id":"snp:argocd:v3.4.5",` +
		`"relative_path":"docs/operator-manual/health.md","heading_breadcrumb":["Sync waves"],"raw_sha256":"sha256:` + strings.Repeat("b", 64) + `","payload_sha256":"sha256:` + strings.Repeat("c", 64) + `",` +
		`"payload_object_path":"normalized/sha256/cc/` + strings.Repeat("c", 64) + `","payload_byte_size":256,"raw_byte_start":100,"raw_byte_end":356,"raw_line_start":8,"raw_line_end":11,` +
		`"fetched_at":"2026-07-16T08:00:00Z","observed_at":"2026-07-16T08:00:00Z","access_scope":"public","fresh_until":"2026-07-17T08:00:00Z",` +
		`"trust_envelope_id":"` + retrievalID("trust-envelope:", "f") + `","content_class":"untrusted_source_data","instruction_policy":"forbidden","execution_policy":"never","tool_policy":"never","interpretation_policy":"evidence_only"},` +
		`"excerpt":"sync waves","excerpt_truncated":false}]}`
}

func retrievalID(prefix, digit string) string {
	return prefix + "sha256:" + strings.Repeat(digit, 64)
}

// blockingRetrievalFixture builds a retrieval child that spawns a grandchild and
// then blocks forever, so cancellation, deadline and process-group reaping are
// all observable. It returns the provider and both published PID files.
func blockingRetrievalFixture(t *testing.T, commandTimeout time.Duration) (*retrievalProvider, string, string) {
	t.Helper()
	directory := t.TempDir()
	executable := filepath.Join(directory, "retrieval")
	childPIDPath := filepath.Join(directory, "child.pid")
	grandchildPIDPath := filepath.Join(directory, "grandchild.pid")
	script := "#!/bin/sh\n" +
		"[ \"$1\" = \"current-query\" ] || exit 9\n" +
		"sleep 300 &\n" +
		"printf '%s\\n' \"$!\" > " + grandchildPIDPath + "\n" +
		"printf '%s\\n' \"$$\" > " + childPIDPath + "\n" +
		"wait\n"
	if err := os.WriteFile(executable, []byte(script), 0o555); err != nil {
		t.Fatal(err)
	}
	digest, _, err := hashBoundFile(executable, maxRetrievalExecutableBytes)
	if err != nil {
		t.Fatal(err)
	}
	return &retrievalProvider{
		configured: true, executable: executable, executableSHA256: strings.TrimPrefix(digest, "sha256:"),
		store: "/store", state: "/state", evidenceStore: "/evidence", admissionPolicy: "/policy",
		admissionPolicyHash: strings.Repeat("c", 64), commandTimeout: commandTimeout,
		now: func() time.Time { return time.Unix(0, 0).UTC() },
	}, childPIDPath, grandchildPIDPath
}

// awaitPID blocks until the retrieval fixture publishes a PID, proving the child
// really started before the test cancels it.
func awaitPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if pid := readPID(path); pid > 0 {
			return pid
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("retrieval child never published a PID at %s", path)
	return 0
}

func readPID(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

// requireProcessReaped fails unless the PID has left the process table, which is
// what separates a reaped process group from an orphaned one.
func requireProcessReaped(t *testing.T, pid int, label string) {
	t.Helper()
	if pid <= 0 {
		t.Fatalf("%s never published a usable PID", label)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s (pid %d) survived the aborted call: it was orphaned, not reaped", label, pid)
}

// requireDegradedRetrieval asserts the fail-closed contract: an aborted
// retrieval is a typed backend_unavailable failure carrying no evidence, never
// a silently-empty success.
func requireDegradedRetrieval(t *testing.T, result toolOutcome, expectedMessage string) {
	t.Helper()
	if !result.Error || result.State != stateBackendUnavailable {
		t.Fatalf("aborted retrieval did not fail closed as backend_unavailable: %#v", result)
	}
	if result.Data["result_state"] != "backend_unavailable" {
		t.Fatalf("aborted retrieval lost its typed result_state: %#v", result.Data)
	}
	if _, ok := result.Data["results"]; ok {
		t.Fatalf("aborted retrieval returned evidence instead of a degraded outcome: %#v", result.Data)
	}
	message, _ := result.Data["message"].(string)
	if !strings.Contains(message, expectedMessage) {
		t.Fatalf("aborted retrieval reported %q, expected it to contain %q", message, expectedMessage)
	}
}

func evidenceQuery() map[string]json.RawMessage {
	return map[string]json.RawMessage{"query": json.RawMessage(`"sync"`)}
}

// A caller cancellation must reach the child: without the threaded context the
// call would instead run to the one-minute lane bound.
func TestEvidenceSearchCallerCancellationReapsTheChildAndFailsClosed(t *testing.T) {
	provider, childPIDPath, grandchildPIDPath := blockingRetrievalFixture(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type completion struct {
		result  toolOutcome
		elapsed time.Duration
	}
	done := make(chan completion, 1)
	go func() {
		started := time.Now()
		result := provider.search(ctx, evidenceQuery())
		done <- completion{result: result, elapsed: time.Since(started)}
	}()

	childPID := awaitPID(t, grandchildPIDPath)
	parentPID := awaitPID(t, childPIDPath)
	cancel()

	var finished completion
	select {
	case finished = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("cancelled retrieval never returned: the caller context is not threaded into the child")
	}
	if finished.elapsed >= time.Minute {
		t.Fatalf("cancellation waited for the lane bound instead of returning early: %s", finished.elapsed)
	}
	requireDegradedRetrieval(t, finished.result, "cancelled by the caller")
	requireProcessReaped(t, parentPID, "retrieval child")
	requireProcessReaped(t, childPID, "retrieval grandchild")
}

// min(caller deadline, lane timeout) must pick the caller's shorter deadline.
func TestEvidenceSearchHonoursACallerDeadlineShorterThanTheLaneTimeout(t *testing.T) {
	provider, childPIDPath, grandchildPIDPath := blockingRetrievalFixture(t, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	started := time.Now()
	result := provider.search(ctx, evidenceQuery())
	elapsed := time.Since(started)

	if elapsed >= 30*time.Second {
		t.Fatalf("the lane bound overrode the shorter caller deadline: %s", elapsed)
	}
	requireDegradedRetrieval(t, result, "exceeded the caller deadline")
	requireProcessReaped(t, readPID(childPIDPath), "retrieval child")
	requireProcessReaped(t, readPID(grandchildPIDPath), "retrieval grandchild")
}

// min(caller deadline, lane timeout) must still fire the lane bound when the
// caller supplies no deadline at all. This is the safety property.
func TestEvidenceSearchKeepsTheLaneTimeoutWithoutACallerDeadline(t *testing.T) {
	provider, childPIDPath, grandchildPIDPath := blockingRetrievalFixture(t, 300*time.Millisecond)

	started := time.Now()
	result := provider.search(context.Background(), evidenceQuery())
	elapsed := time.Since(started)

	if elapsed >= 30*time.Second {
		t.Fatalf("the lane bound no longer terminates an unbounded caller: %s", elapsed)
	}
	requireDegradedRetrieval(t, result, "timed out")
	requireProcessReaped(t, readPID(childPIDPath), "retrieval child")
	requireProcessReaped(t, readPID(grandchildPIDPath), "retrieval grandchild")
}

// Threading the context must not disturb the successful path.
func TestEvidenceSearchUnderALiveCallerContextIsUnchanged(t *testing.T) {
	provider := currentRetrievalFixture(t, currentRetrievalOKResponse(), "2026-07-16T10:34:56Z")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := provider.search(ctx, evidenceQuery())
	if result.Error || result.State != stateOK || result.Data["result_state"] != "ok" {
		t.Fatalf("a live caller context changed the successful contract: %#v", result)
	}
	if result.Data["retrieval_state"] != "current" || result.Data["authority_state"] != "evaluated_current" {
		t.Fatalf("signed current authority was lost under a caller context: %#v", result.Data)
	}
	hits, ok := result.Data["results"].([]currentRetrievalHit)
	if !ok || len(hits) != 1 || hits[0].Evidence.SpanID != retrievalID("evidence-span:", "a") {
		t.Fatalf("exact citation was lost under a caller context: %#v", result.Data["results"])
	}

	// Cancelling after completion must not retroactively degrade the result.
	cancel()
	if result.Error || result.State != stateOK {
		t.Fatalf("a post-completion cancel mutated a finished result: %#v", result)
	}
}

// Federation lanes must observe caller cancellation, drain their workers and
// refuse to fuse partial evidence into a usable answer.
func TestRetrievalFederationCancellationDrainsWorkersAndFailsClosed(t *testing.T) {
	provider, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
		{laneID: "alpha", state: "/state-alpha", response: currentRetrievalOKResponseFor("alpha", "c")},
		{laneID: "beta", state: "/state-beta", response: currentRetrievalOKResponseFor("beta", "d")},
	}, "2026-07-16T10:34:56Z")

	baseline := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := provider.search(ctx, evidenceQuery())
	if !result.Error || result.State != stateBackendUnavailable {
		t.Fatalf("cancelled federation did not fail closed: %#v", result)
	}
	if result.Data["error_code"] != "federation_cancelled" {
		t.Fatalf("cancelled federation was not reported as a cancellation: %#v", result.Data)
	}
	if hits, ok := result.Data["results"].([]federatedRetrievalHit); !ok || len(hits) != 0 {
		t.Fatalf("cancelled federation returned fused evidence: %#v", result.Data["results"])
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("federation workers leaked: %d goroutines against a %d baseline", runtime.NumGoroutine(), baseline)
}
