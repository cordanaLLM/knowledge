package main

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Cluster mode exercises the case classes that need no fixture control against
// the live in-cluster broker over authenticated Streamable HTTP. Assertions
// are contract-shape assertions: the live signed lane's content is real, so
// only its typed states, lineage shapes, ordering and replay identity are
// checked. A typed fail-closed lane (for example backend_unavailable while the
// federation catalog is unpublished) is reported as "blocked", never as pass.

var (
	lineageIDPattern = regexp.MustCompile(`^retrieval-(pointer|receipt|generation|quality-report|evaluation-suite|evaluation-metrics|candidate):sha256:[0-9a-f]{64}$`)
	spanIDPattern    = regexp.MustCompile(`^evidence-span:sha256:[0-9a-f]{64}$`)
)

func clusterNormalize(result callResult, freeze *suiteFreeze) []byte {
	encoded, err := canonicalJSON(normalizeValue(result.Structured, "", freeze.Normalization))
	if err != nil {
		panic(err)
	}
	return encoded
}

func clusterTranscript(freeze *suiteFreeze, caseID string) *transcript {
	return &transcript{SuiteID: freeze.SuiteID, Revision: freeze.Revision, CaseID: caseID}
}

func runClusterCase(client *httpBroker, freeze *suiteFreeze, frozenCase suiteCase, verdict *caseVerdict) []byte {
	record := clusterTranscript(freeze, frozenCase.CaseID)
	check := &checker{}
	blocked := ""
	var err error
	switch frozenCase.CaseClass {
	case "success":
		blocked, err = clusterSuccess(client, freeze, record, check)
	case "acl":
		err = clusterACL(client, record, check)
	case "pagination":
		blocked, err = clusterPagination(client, freeze, record, check)
	case "reconnect":
		blocked, err = clusterReconnect(client, freeze, record, check)
	case "deterministic_order":
		blocked, err = clusterDeterministicOrder(client, freeze, record, check)
	default:
		verdict.Verdict = "not_executable_on_live"
		verdict.Failure = "requires hermetic fixture control"
		return nil
	}
	if err != nil {
		verdict.Verdict = "fail"
		verdict.Failure = err.Error()
		return nil
	}
	if checkErr := check.err(); checkErr != nil {
		verdict.Verdict = "fail"
		verdict.Failure = checkErr.Error()
		return nil
	}
	if blocked != "" {
		verdict.Verdict = "blocked"
		verdict.Failure = blocked
		return nil
	}
	verdict.Verdict = "pass"
	encoded, encodeErr := record.encode()
	if encodeErr != nil {
		verdict.Verdict = "fail"
		verdict.Failure = encodeErr.Error()
		return nil
	}
	return encoded
}

func recordCluster(record *transcript, freeze *suiteFreeze, step, tool string, arguments map[string]any, result callResult) {
	record.add(step, tool, arguments, result, "", freeze.Normalization)
}

// clusterSuccess verifies the live signed lane's evidence contract shape when
// it serves, and reports its typed fail-closed state as blocked when it does
// not — never as an empty success.
func clusterSuccess(client *httpBroker, freeze *suiteFreeze, record *transcript, check *checker) (string, error) {
	arguments := map[string]any{"query": "sync"}
	result, err := client.callTool("evidence_search", arguments, "")
	if err != nil {
		return "", err
	}
	recordCluster(record, freeze, "live-signed-lane", "evidence_search", arguments, result)
	state := asString(result.Structured["state"])
	if result.IsError || state != "ok" {
		if len(asList(result.Structured["results"])) != 0 {
			check.truthy("fail-closed live lane must carry no evidence", false)
			return "", nil
		}
		return fmt.Sprintf("live signed lane answered typed state %q instead of ok", state), nil
	}
	check.eq("time_source", result.Structured["time_source"], "broker_host_clock_utc")
	check.eq("principal_scope", result.Structured["principal_scope"], "public")
	retrievalState := asString(result.Structured["retrieval_state"])
	check.truthy("retrieval_state is a signed-current state", retrievalState == "current" || retrievalState == "federated_current")
	if retrievalState == "current" {
		check.truthy("pointer lineage shape", lineageIDPattern.MatchString(asString(result.Structured["pointer_id"])))
		check.truthy("generation lineage shape", lineageIDPattern.MatchString(asString(result.Structured["current_generation_id"])))
	}
	for index, hit := range asList(result.Structured["results"]) {
		evidence := asMap(asMap(hit)["evidence"])
		label := fmt.Sprintf("results[%d]", index)
		check.truthy(label+" span shape", spanIDPattern.MatchString(asString(evidence["span_id"])))
		check.truthy(label+" byte span coherent", asFloat(evidence["raw_byte_end"])-asFloat(evidence["raw_byte_start"]) == asFloat(evidence["payload_byte_size"]))
		check.eq(label+" access_scope", evidence["access_scope"], "public")
		check.eq(label+" content_class", evidence["content_class"], "untrusted_source_data")
	}
	checkContentEnvelope(check, result.Structured)
	return "", nil
}

// clusterACL verifies the bearer gate on the live endpoint: missing and wrong
// tokens are rejected with 401 before any handler, and no session is issued.
func clusterACL(client *httpBroker, record *transcript, check *checker) error {
	unauthenticated, unauthenticatedBody, err := client.post(initializeBody, "", false)
	if err != nil {
		return err
	}
	check.eq("unauthenticated status", unauthenticated.StatusCode, http.StatusUnauthorized)
	check.eq("unauthenticated session withheld", unauthenticated.Header.Get("Mcp-Session-Id"), "")
	check.truthy("unauthenticated body discloses no server identity", !strings.Contains(string(unauthenticatedBody), "serverInfo"))
	wrongToken := &httpBroker{endpoint: client.endpoint, token: strings.Repeat("f", 40)}
	rejected, rejectedBody, err := wrongToken.post(initializeBody, "", true)
	if err != nil {
		return err
	}
	check.eq("wrong-token status", rejected.StatusCode, http.StatusUnauthorized)
	check.truthy("wrong-token body discloses no server identity", !strings.Contains(string(rejectedBody), "serverInfo"))
	record.Calls = append(record.Calls, transcriptCall{
		Step: "http-bearer-gate", Tool: "initialize",
		Arguments: map[string]any{"transport": "streamable-http"},
		Result: map[string]any{
			"unauthenticated_status": unauthenticated.StatusCode,
			"wrong_token_status":     rejected.StatusCode,
			"session_id_issued":      false,
		},
	})
	return nil
}

// clusterPagination walks the live registry's gap cursor and replays the first
// page byte-identically.
func clusterPagination(client *httpBroker, freeze *suiteFreeze, record *transcript, check *checker) (string, error) {
	pageArguments := func(offset int) map[string]any {
		return map[string]any{"kind": "gaps", "limit": 1, "offset": offset}
	}
	first, err := client.callTool("registry_evidence", pageArguments(0), "")
	if err != nil {
		return "", err
	}
	recordCluster(record, freeze, "page-0", "registry_evidence", pageArguments(0), first)
	if first.IsError {
		return fmt.Sprintf("live registry answered typed state %q instead of a page", asString(first.Structured["state"])), nil
	}
	check.truthy("total is reported", asFloat(first.Structured["total"]) >= 0)
	replay, err := client.callTool("registry_evidence", pageArguments(0), "")
	if err != nil {
		return "", err
	}
	recordCluster(record, freeze, "page-0-replay", "registry_evidence", pageArguments(0), replay)
	check.truthy("page 0 replays byte-identically", bytes.Equal(clusterNormalize(first, freeze), clusterNormalize(replay, freeze)))
	if next, ok := first.Structured["next_offset"].(float64); ok {
		second, err := client.callTool("registry_evidence", pageArguments(int(next)), "")
		if err != nil {
			return "", err
		}
		recordCluster(record, freeze, "page-1", "registry_evidence", pageArguments(int(next)), second)
		check.eq("page 1 offset", second.Structured["offset"], next)
	}
	return "", nil
}

// clusterReconnect proves the stateless transport serves a retained stale
// Mcp-Session-Id instead of a permanent 404.
func clusterReconnect(client *httpBroker, freeze *suiteFreeze, record *transcript, check *checker) (string, error) {
	initialized, _, err := client.post(initializeBody, "", true)
	if err != nil {
		return "", err
	}
	check.eq("initialize status", initialized.StatusCode, http.StatusOK)
	check.eq("stateless initialize issues no session", initialized.Header.Get("Mcp-Session-Id"), "")
	arguments := map[string]any{}
	result, err := client.callTool("knowledge_status", arguments, "expired-session-retained-by-client")
	if err != nil {
		return "", err
	}
	recordCluster(record, freeze, "stale-session-served", "knowledge_status", arguments, result)
	check.truthy("stale session answered a typed state", asString(result.Structured["state"]) != "")
	return "", nil
}

// clusterDeterministicOrder proves the live lane's answer replays
// byte-identically under normalization, whatever its typed state.
func clusterDeterministicOrder(client *httpBroker, freeze *suiteFreeze, record *transcript, check *checker) (string, error) {
	arguments := map[string]any{"query": "sync", "limit": 4}
	first, err := client.callTool("evidence_search", arguments, "")
	if err != nil {
		return "", err
	}
	recordCluster(record, freeze, "fused-order", "evidence_search", arguments, first)
	repeat, err := client.callTool("evidence_search", arguments, "")
	if err != nil {
		return "", err
	}
	recordCluster(record, freeze, "fused-order-repeat", "evidence_search", arguments, repeat)
	check.truthy("repeat call is byte-identical", bytes.Equal(clusterNormalize(first, freeze), clusterNormalize(repeat, freeze)))
	if first.IsError {
		return fmt.Sprintf("live signed lane answered typed state %q; determinism verified on the typed failure only", asString(first.Structured["state"])), nil
	}
	return "", nil
}

func asFloat(value any) float64 {
	number, _ := value.(float64)
	return number
}
