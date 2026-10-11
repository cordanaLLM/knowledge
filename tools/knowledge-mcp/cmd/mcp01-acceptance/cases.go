package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Frozen fixture identities the cases assert against; these mirror the pinned
// response fixtures byte for byte.
var (
	alphaSpan       = "evidence-span:sha256:" + strings.Repeat("a", 64)
	betaSpan        = "evidence-span:sha256:" + strings.Repeat("ea", 32)
	alphaPointer    = "retrieval-pointer:sha256:" + strings.Repeat("1", 64)
	alphaGeneration = "retrieval-generation:sha256:" + strings.Repeat("3", 64)
	alphaSuite      = "retrieval-evaluation-suite:sha256:" + strings.Repeat("6", 64)
	alphaRawSHA     = "sha256:" + strings.Repeat("b", 64)
	rolloutsMarkers = []string{"argo-rollouts", "snp:argorollouts"}
)

// checker accumulates assertion failures so a case reports every violated
// contract clause instead of only the first.
type checker struct {
	failures []string
}

func (check *checker) eq(label string, got, want any) {
	if !reflect.DeepEqual(got, want) {
		check.failures = append(check.failures, fmt.Sprintf("%s: got %#v, want %#v", label, got, want))
	}
}

func (check *checker) truthy(label string, ok bool) {
	if !ok {
		check.failures = append(check.failures, label)
	}
}

func (check *checker) contains(label, haystack, needle string) {
	if !strings.Contains(haystack, needle) {
		check.failures = append(check.failures, fmt.Sprintf("%s: %q does not contain %q", label, haystack, needle))
	}
}

func (check *checker) err() error {
	if len(check.failures) == 0 {
		return nil
	}
	return errors.New(strings.Join(check.failures, "; "))
}

func asString(value any) string {
	text, _ := value.(string)
	return text
}

func asList(value any) []any {
	list, _ := value.([]any)
	return list
}

func asMap(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

// caseContext carries everything a hermetic case needs.
type caseContext struct {
	ws         *workspace
	freeze     *suiteFreeze
	brokerPath string
	suiteDir   string
	notes      []string
}

func (ctx *caseContext) note(format string, values ...any) {
	ctx.notes = append(ctx.notes, fmt.Sprintf(format, values...))
}

func (ctx *caseContext) spawn(arguments []string) (*stdioBroker, error) {
	broker, err := startStdioBroker(ctx.brokerPath, arguments)
	if err != nil {
		return nil, err
	}
	if err := broker.initialize(); err != nil {
		broker.close()
		return nil, err
	}
	return broker, nil
}

func (ctx *caseContext) newTranscript(caseID string) *transcript {
	return &transcript{SuiteID: ctx.freeze.SuiteID, Revision: ctx.freeze.Revision, CaseID: caseID}
}

func (ctx *caseContext) record(record *transcript, step, tool string, arguments map[string]any, result callResult) {
	record.add(step, tool, arguments, result, ctx.ws.root, ctx.freeze.Normalization)
}

func evidenceQuery(limit int) map[string]any {
	arguments := map[string]any{"query": "sync"}
	if limit > 0 {
		arguments["limit"] = limit
	}
	return arguments
}

// checkContentEnvelope asserts the hostile-content envelope every tool result
// must carry.
func checkContentEnvelope(check *checker, structured map[string]any) {
	envelope := asMap(structured["content_envelope"])
	check.eq("content_envelope.content_role", envelope["content_role"], "untrusted_data_only")
	check.eq("content_envelope.instructions_forbidden", envelope["instructions_forbidden"], true)
	check.eq("content_envelope.executable", envelope["executable"], false)
}

// caseSuccess proves the signed-current single-lane contract: typed ok, full
// pointer/generation/evaluation lineage, exact span citation and trust
// envelope, broker-supplied UTC time and pinned executable/policy identity.
func caseSuccess(ctx *caseContext) (*transcript, error) {
	if err := ctx.ws.installResponse("solo", "alpha-ok.json"); err != nil {
		return nil, err
	}
	broker, err := ctx.spawn(ctx.ws.soloArguments())
	if err != nil {
		return nil, err
	}
	defer broker.close()
	result, err := broker.callTool("evidence_search", evidenceQuery(0))
	if err != nil {
		return nil, err
	}
	record := ctx.newTranscript("success")
	ctx.record(record, "signed-current-ok", "evidence_search", evidenceQuery(0), result)
	check := &checker{}
	check.eq("isError", result.IsError, false)
	data := result.Structured
	check.eq("state", data["state"], "ok")
	check.eq("result_state", data["result_state"], "ok")
	check.eq("retrieval_state", data["retrieval_state"], "current")
	check.eq("authority_state", data["authority_state"], "evaluated_current")
	check.eq("serving_eligible", data["serving_eligible"], true)
	check.eq("current_eligible", data["current_eligible"], true)
	check.eq("pointer_id", data["pointer_id"], alphaPointer)
	check.eq("pointer_revision", data["pointer_revision"], float64(7))
	check.eq("current_generation_id", data["current_generation_id"], alphaGeneration)
	check.eq("evaluation_dataset_id", data["evaluation_dataset_id"], alphaSuite)
	check.eq("generation_created_at", data["generation_created_at"], "2026-07-16T09:00:00Z")
	check.eq("freshness_state", data["freshness_state"], "fresh")
	check.eq("time_source", data["time_source"], "broker_host_clock_utc")
	check.eq("principal_scope", data["principal_scope"], "public")
	check.eq("retrieval_executable_sha256", data["retrieval_executable_sha256"], "sha256:"+ctx.ws.scriptPin)
	check.eq("retrieval_admission_policy_sha256", data["retrieval_admission_policy_sha256"], "sha256:"+ctx.ws.policyPins["alpha"])
	if _, parseErr := time.Parse("2006-01-02T15:04:05Z", asString(data["observed_at"])); parseErr != nil {
		check.truthy("observed_at is canonical broker UTC", false)
	}
	results := asList(data["results"])
	check.eq("result count", len(results), 1)
	if len(results) == 1 {
		hit := asMap(results[0])
		check.eq("hit.score", hit["score"], float64(3))
		check.eq("hit.excerpt", hit["excerpt"], "sync waves")
		evidence := asMap(hit["evidence"])
		check.eq("evidence.span_id", evidence["span_id"], alphaSpan)
		check.eq("evidence.source_id", evidence["source_id"], "src:github:argoproj/argo-cd@v3.4.5:docs")
		check.eq("evidence.raw_sha256", evidence["raw_sha256"], alphaRawSHA)
		check.eq("evidence.relative_path", evidence["relative_path"], "docs/operator-manual/health.md")
		check.eq("evidence.raw_byte_start", evidence["raw_byte_start"], float64(100))
		check.eq("evidence.raw_byte_end", evidence["raw_byte_end"], float64(356))
		check.eq("evidence.raw_line_start", evidence["raw_line_start"], float64(8))
		check.eq("evidence.raw_line_end", evidence["raw_line_end"], float64(11))
		check.eq("evidence.access_scope", evidence["access_scope"], "public")
		check.eq("evidence.content_class", evidence["content_class"], "untrusted_source_data")
		check.eq("evidence.instruction_policy", evidence["instruction_policy"], "forbidden")
		check.eq("evidence.interpretation_policy", evidence["interpretation_policy"], "evidence_only")
	}
	checkContentEnvelope(check, data)
	return record, check.err()
}

// caseStale proves a stale signed generation stays a typed error with retained
// lineage and zero evidence — never converted into an empty success.
func caseStale(ctx *caseContext) (*transcript, error) {
	if err := ctx.ws.installResponse("solo", "solo-stale.json"); err != nil {
		return nil, err
	}
	broker, err := ctx.spawn(ctx.ws.soloArguments())
	if err != nil {
		return nil, err
	}
	defer broker.close()
	result, err := broker.callTool("evidence_search", evidenceQuery(0))
	if err != nil {
		return nil, err
	}
	record := ctx.newTranscript("stale")
	ctx.record(record, "stale-typed", "evidence_search", evidenceQuery(0), result)
	check := &checker{}
	check.eq("isError", result.IsError, true)
	data := result.Structured
	check.eq("state", data["state"], "stale")
	check.eq("result_state", data["result_state"], "stale")
	check.contains("message", asString(data["message"]), "stale")
	check.eq("freshness_state", data["freshness_state"], "stale")
	check.eq("serving_eligible", data["serving_eligible"], false)
	check.eq("results", len(asList(data["results"])), 0)
	check.eq("pointer lineage retained", data["pointer_id"], alphaPointer)
	return record, check.err()
}

// caseOneLaneTimeout proves a wedged lane hits the broker's fixed 20s deadline,
// is reported as a visible degraded lane, and never suppresses the healthy
// lane's evidence or converts into an empty success.
func caseOneLaneTimeout(ctx *caseContext) (*transcript, error) {
	if err := ctx.ws.installResponse("alpha", "alpha-ok.json"); err != nil {
		return nil, err
	}
	if err := ctx.ws.installResponse("beta", "beta-ok.json"); err != nil {
		return nil, err
	}
	if err := ctx.ws.setBlock("beta", true); err != nil {
		return nil, err
	}
	defer func() { _ = ctx.ws.setBlock("beta", false) }()
	broker, err := ctx.spawn(ctx.ws.federationArguments("fed-ok"))
	if err != nil {
		return nil, err
	}
	defer broker.close()
	started := time.Now()
	result, err := broker.callTool("evidence_search", evidenceQuery(2))
	elapsed := time.Since(started)
	if err != nil {
		return nil, err
	}
	ctx.note("blocked lane rode the fixed deadline: elapsed %s", elapsed.Round(time.Millisecond))
	record := ctx.newTranscript("one_lane_timeout")
	ctx.record(record, "one-lane-timeout-partial", "evidence_search", evidenceQuery(2), result)
	check := &checker{}
	check.eq("isError", result.IsError, false)
	data := result.Structured
	check.eq("state", data["state"], "partial")
	check.eq("result_state", data["result_state"], "partial")
	check.eq("retrieval_state", data["retrieval_state"], "federated_partial")
	check.eq("lane_count", data["lane_count"], float64(2))
	check.eq("current_lane_count", data["current_lane_count"], float64(1))
	check.eq("degraded_lane_count", data["degraded_lane_count"], float64(1))
	lanes := asList(data["lanes"])
	check.eq("lane descriptors", len(lanes), 2)
	if len(lanes) == 2 {
		beta := asMap(lanes[1])
		check.eq("beta lane_id", beta["lane_id"], "beta")
		check.eq("beta state", beta["state"], "backend_unavailable")
		check.contains("beta message", asString(beta["message"]), "timed out")
	}
	results := asList(data["results"])
	check.eq("healthy lane evidence", len(results), 1)
	if len(results) == 1 {
		check.eq("surviving span", asMap(asMap(results[0])["evidence"])["span_id"], alphaSpan)
	}
	check.truthy(fmt.Sprintf("elapsed %s respects the fixed 20s lane deadline", elapsed), elapsed >= 19*time.Second && elapsed < 55*time.Second)
	return record, check.err()
}

// caseTamper proves every artifact boundary fails closed on a single mutated
// byte: the suite's own fixture pins, the pinned lane executable, and the
// pinned federation catalog — and that restoring the frozen bytes recovers.
func caseTamper(ctx *caseContext) (*transcript, error) {
	check := &checker{}
	// Negative control: a copied suite tree with one flipped fixture byte must
	// be rejected by the runner's own pin verification.
	tamperedSuite, err := copySuiteTree(ctx.suiteDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tamperedSuite) }()
	if err := tamperFile(filepath.Join(tamperedSuite, "fixtures", "responses", "alpha-ok.json")); err != nil {
		return nil, err
	}
	pinErr := verifyFixturePins(tamperedSuite, ctx.freeze)
	check.truthy("one flipped fixture byte is detected by pin verification", pinErr != nil)
	if pinErr != nil {
		check.contains("pin verification failure", pinErr.Error(), "does not match its frozen pin")
	}

	if err := ctx.ws.installResponse("solo", "alpha-ok.json"); err != nil {
		return nil, err
	}
	broker, err := ctx.spawn(ctx.ws.soloArguments())
	if err != nil {
		return nil, err
	}
	defer broker.close()
	record := ctx.newTranscript("tamper")
	before, err := broker.callTool("evidence_search", evidenceQuery(0))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "pinned-executable-serves", "evidence_search", evidenceQuery(0), before)
	check.eq("pre-tamper state", before.Structured["state"], "ok")
	if err := tamperFile(ctx.ws.scriptPath); err != nil {
		return nil, err
	}
	tampered, err := broker.callTool("evidence_search", evidenceQuery(0))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "tampered-executable-fails-closed", "evidence_search", evidenceQuery(0), tampered)
	check.eq("tampered executable isError", tampered.IsError, true)
	check.eq("tampered executable state", tampered.Structured["state"], "backend_unavailable")
	check.contains("tampered executable message", asString(tampered.Structured["message"]), "does not match the operator pin")
	_, tamperedHasResults := tampered.Structured["results"]
	check.eq("tampered executable returned no evidence", tamperedHasResults, false)
	if err := ctx.ws.restoreFixtureFile("fixtures/lane-child.sh", ctx.ws.scriptPath, 0o555); err != nil {
		return nil, err
	}
	restored, err := broker.callTool("evidence_search", evidenceQuery(0))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "restored-executable-recovers", "evidence_search", evidenceQuery(0), restored)
	check.eq("restored executable state", restored.Structured["state"], "ok")

	// Catalog tamper: the federation authority is the externally pinned catalog.
	if err := ctx.ws.installResponse("alpha", "alpha-ok.json"); err != nil {
		return nil, err
	}
	if err := ctx.ws.installResponse("beta", "beta-ok.json"); err != nil {
		return nil, err
	}
	federated, err := ctx.spawn(ctx.ws.federationArguments("fed-tamper"))
	if err != nil {
		return nil, err
	}
	defer federated.close()
	healthy, err := federated.callTool("evidence_search", evidenceQuery(2))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "pinned-catalog-serves", "evidence_search", evidenceQuery(2), healthy)
	check.eq("pre-tamper catalog state", healthy.Structured["retrieval_state"], "federated_current")
	if err := tamperFile(ctx.ws.catalogs["fed-tamper"].path); err != nil {
		return nil, err
	}
	catalogTampered, err := federated.callTool("evidence_search", evidenceQuery(2))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "tampered-catalog-fails-closed", "evidence_search", evidenceQuery(2), catalogTampered)
	check.eq("tampered catalog isError", catalogTampered.IsError, true)
	check.eq("tampered catalog error_code", catalogTampered.Structured["error_code"], "federation_catalog_invalid")
	check.contains("tampered catalog message", asString(catalogTampered.Structured["message"]), "SHA-256 does not match the operator pin")
	check.eq("tampered catalog lanes withheld", len(asList(catalogTampered.Structured["lanes"])), 0)
	check.eq("tampered catalog evidence withheld", len(asList(catalogTampered.Structured["results"])), 0)
	if err := ctx.ws.restoreCatalog("fed-tamper"); err != nil {
		return nil, err
	}
	catalogRestored, err := federated.callTool("evidence_search", evidenceQuery(2))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "restored-catalog-recovers", "evidence_search", evidenceQuery(2), catalogRestored)
	check.eq("restored catalog state", catalogRestored.Structured["retrieval_state"], "federated_current")
	return record, check.err()
}

// caseConflict proves one span ID with conflicting citation bytes fails the
// whole federated request closed, deterministically, with zero evidence.
func caseConflict(ctx *caseContext) (*transcript, error) {
	if err := ctx.ws.installResponse("alpha", "alpha-ok.json"); err != nil {
		return nil, err
	}
	if err := ctx.ws.installResponse("beta", "beta-conflict.json"); err != nil {
		return nil, err
	}
	broker, err := ctx.spawn(ctx.ws.federationArguments("fed-ok"))
	if err != nil {
		return nil, err
	}
	defer broker.close()
	record := ctx.newTranscript("conflict")
	first, err := broker.callTool("evidence_search", evidenceQuery(2))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "span-conflict-fails-closed", "evidence_search", evidenceQuery(2), first)
	second, err := broker.callTool("evidence_search", evidenceQuery(2))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "span-conflict-repeat", "evidence_search", evidenceQuery(2), second)
	check := &checker{}
	check.eq("isError", first.IsError, true)
	check.eq("state", first.Structured["state"], "backend_unavailable")
	check.eq("error_code", first.Structured["error_code"], "federation_span_conflict")
	check.contains("message", asString(first.Structured["message"]), "conflicting content")
	check.eq("retrieval_state", first.Structured["retrieval_state"], "federated_unavailable")
	check.eq("evidence withheld", len(asList(first.Structured["results"])), 0)
	firstBytes := mustNormalize(first, ctx)
	secondBytes := mustNormalize(second, ctx)
	check.truthy("conflict failure is deterministic across calls", bytes.Equal(firstBytes, secondBytes))
	return record, check.err()
}

// caseACL encodes the broker's real authorization boundaries: admission-policy
// authorization runs before any lane metadata is disclosed, a non-public
// evidence scope is rejected before disclosure, a policy-forbidden query stays
// a typed forbidden, and the HTTP bearer gate 401s before any handler runs.
func caseACL(ctx *caseContext) (*transcript, error) {
	record := ctx.newTranscript("acl")
	check := &checker{}

	denied, err := ctx.spawn(ctx.ws.federationArguments("fed-acl"))
	if err != nil {
		return nil, err
	}
	defer denied.close()
	deniedResult, err := denied.callTool("evidence_search", evidenceQuery(0))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "admission-denied-before-metadata", "evidence_search", evidenceQuery(0), deniedResult)
	check.eq("denied isError", deniedResult.IsError, true)
	check.eq("denied state", deniedResult.Structured["state"], "backend_unavailable")
	check.eq("denied error_code", deniedResult.Structured["error_code"], "federation_catalog_invalid")
	check.contains("denied message", asString(deniedResult.Structured["message"]), "does not authorize one active public source")
	check.eq("denied lanes withheld", len(asList(deniedResult.Structured["lanes"])), 0)
	check.eq("denied evidence withheld", len(asList(deniedResult.Structured["results"])), 0)
	if disclosure := assertNoDisclosure(mustNormalize(deniedResult, ctx), rolloutsMarkers...); disclosure != nil {
		check.truthy(disclosure.Error(), false)
	}

	if err := ctx.ws.installResponse("solo", "solo-private-scope.json"); err != nil {
		return nil, err
	}
	solo, err := ctx.spawn(ctx.ws.soloArguments())
	if err != nil {
		return nil, err
	}
	defer solo.close()
	scoped, err := solo.callTool("evidence_search", evidenceQuery(0))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "non-public-scope-withheld", "evidence_search", evidenceQuery(0), scoped)
	check.eq("scoped isError", scoped.IsError, true)
	check.eq("scoped state", scoped.Structured["state"], "backend_unavailable")
	check.contains("scoped message", asString(scoped.Structured["message"]), "trust envelope is invalid")
	if disclosure := assertNoDisclosure(mustNormalize(scoped, ctx), "evidence-span:", "sync waves"); disclosure != nil {
		check.truthy(disclosure.Error(), false)
	}

	if err := ctx.ws.installResponse("solo", "solo-forbidden.json"); err != nil {
		return nil, err
	}
	forbidden, err := solo.callTool("evidence_search", evidenceQuery(0))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "policy-forbidden-typed", "evidence_search", evidenceQuery(0), forbidden)
	check.eq("forbidden isError", forbidden.IsError, true)
	check.eq("forbidden state", forbidden.Structured["state"], "forbidden")
	check.eq("forbidden error_code", forbidden.Structured["error_code"], "query-forbidden")
	check.eq("forbidden evidence withheld", len(asList(forbidden.Structured["results"])), 0)

	if err := ctx.runHTTPAuthChecks(record, check); err != nil {
		return nil, err
	}
	return record, check.err()
}

// caseDeletion encodes the broker's deletion semantics: a deleted, tombstoned
// or absent source fails the whole lane closed at admission-policy load, before
// any lane metadata or evidence is disclosed.
func caseDeletion(ctx *caseContext) (*transcript, error) {
	record := ctx.newTranscript("deletion")
	check := &checker{}
	for _, variant := range []struct{ catalog, step string }{
		{"fed-del-deleted", "deletion-state-deleted"},
		{"fed-del-tombstone", "tombstoned-source"},
		{"fed-del-absent", "source-state-absent"},
	} {
		broker, err := ctx.spawn(ctx.ws.federationArguments(variant.catalog))
		if err != nil {
			return nil, err
		}
		result, err := broker.callTool("evidence_search", evidenceQuery(0))
		broker.close()
		if err != nil {
			return nil, err
		}
		ctx.record(record, variant.step, "evidence_search", evidenceQuery(0), result)
		check.eq(variant.step+" isError", result.IsError, true)
		check.eq(variant.step+" state", result.Structured["state"], "backend_unavailable")
		check.eq(variant.step+" error_code", result.Structured["error_code"], "federation_catalog_invalid")
		check.contains(variant.step+" message", asString(result.Structured["message"]), "does not authorize one active public source")
		check.eq(variant.step+" lanes withheld", len(asList(result.Structured["lanes"])), 0)
		check.eq(variant.step+" evidence withheld", len(asList(result.Structured["results"])), 0)
		if disclosure := assertNoDisclosure(mustNormalize(result, ctx), rolloutsMarkers...); disclosure != nil {
			check.truthy(variant.step+": "+disclosure.Error(), false)
		}
	}
	return record, check.err()
}

// casePagination proves offset/limit cursors over the candidate registry:
// exact totals, stable page order, byte-identical page replay, typed empty
// out-of-range pages, and candidate authority never upgraded past partial.
func casePagination(ctx *caseContext) (*transcript, error) {
	if err := ctx.ws.installResponse("solo", "alpha-ok.json"); err != nil {
		return nil, err
	}
	broker, err := ctx.spawn(ctx.ws.soloArguments())
	if err != nil {
		return nil, err
	}
	defer broker.close()
	record := ctx.newTranscript("pagination")
	check := &checker{}
	pageArguments := func(offset int) map[string]any {
		return map[string]any{
			"component_id": "cmp-mcp01-root", "direction": "dependencies",
			"limit": 1, "offset": offset,
		}
	}
	expectedTargets := []string{"cmp-mcp01-dep-a", "cmp-mcp01-dep-b", "cmp-mcp01-dep-c"}
	var firstPage callResult
	for page := 0; page < 3; page++ {
		result, err := broker.callTool("registry_relationships", pageArguments(page))
		if err != nil {
			return nil, err
		}
		if page == 0 {
			firstPage = result
		}
		ctx.record(record, fmt.Sprintf("page-%d", page), "registry_relationships", pageArguments(page), result)
		label := fmt.Sprintf("page %d", page)
		check.eq(label+" isError", result.IsError, false)
		check.eq(label+" state stays candidate partial", result.Structured["state"], "partial")
		check.eq(label+" result_state", result.Structured["result_state"], "ok")
		check.eq(label+" total", result.Structured["total"], float64(3))
		check.eq(label+" total_exact", result.Structured["total_exact"], true)
		check.eq(label+" offset", result.Structured["offset"], float64(page))
		if page < 2 {
			check.eq(label+" next_offset", result.Structured["next_offset"], float64(page+1))
		} else {
			check.eq(label+" next_offset terminal", result.Structured["next_offset"], nil)
		}
		items := asList(result.Structured["relationships"])
		check.eq(label+" item count", len(items), 1)
		if len(items) == 1 {
			item := asMap(items[0])
			check.eq(label+" target", item["to_component_id"], expectedTargets[page])
			check.eq(label+" relationship", item["relationship"], "depends_on")
			check.eq(label+" scope", item["scope"], "runtime")
		}
		registry := asMap(result.Structured["registry"])
		check.eq(label+" signed_selection_verified", registry["signed_selection_verified"], false)
	}
	replay, err := broker.callTool("registry_relationships", pageArguments(0))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "page-0-replay", "registry_relationships", pageArguments(0), replay)
	check.truthy("page 0 replays byte-identically", bytes.Equal(mustNormalize(firstPage, ctx), mustNormalize(replay, ctx)))
	beyond, err := broker.callTool("registry_relationships", pageArguments(10))
	if err != nil {
		return nil, err
	}
	ctx.record(record, "page-beyond-total", "registry_relationships", pageArguments(10), beyond)
	check.eq("beyond-total result_state", beyond.Structured["result_state"], "empty")
	check.eq("beyond-total items", len(asList(beyond.Structured["relationships"])), 0)
	check.eq("beyond-total clamped offset", beyond.Structured["offset"], float64(3))
	check.eq("beyond-total next_offset", beyond.Structured["next_offset"], nil)
	return record, check.err()
}

// caseReconnect proves replay identity across a broker restart on stdio and
// the stateless HTTP contract: a retained stale Mcp-Session-Id is served, and
// both transports return the same normalized signed-current object.
func caseReconnect(ctx *caseContext) (*transcript, error) {
	if err := ctx.ws.installResponse("solo", "alpha-ok.json"); err != nil {
		return nil, err
	}
	record := ctx.newTranscript("reconnect")
	check := &checker{}
	first, err := ctx.spawn(ctx.ws.soloArguments())
	if err != nil {
		return nil, err
	}
	before, err := first.callTool("evidence_search", evidenceQuery(0))
	first.close()
	if err != nil {
		return nil, err
	}
	ctx.record(record, "before-restart", "evidence_search", evidenceQuery(0), before)
	second, err := ctx.spawn(ctx.ws.soloArguments())
	if err != nil {
		return nil, err
	}
	after, err := second.callTool("evidence_search", evidenceQuery(0))
	second.close()
	if err != nil {
		return nil, err
	}
	ctx.record(record, "after-restart", "evidence_search", evidenceQuery(0), after)
	check.truthy("restart replays byte-identically", bytes.Equal(mustNormalize(before, ctx), mustNormalize(after, ctx)))

	httpResult, err := ctx.runHTTPReconnect(record, check)
	if err != nil {
		return nil, err
	}
	check.truthy("HTTP and stdio return one normalized signed-current object", bytes.Equal(mustNormalize(before, ctx), mustNormalize(httpResult, ctx)))
	return record, check.err()
}

// caseDeterministicOrder proves fused ordering is a pure function of the
// signed inputs: byte-identical across repeated calls and across processes,
// with the frozen bounded_borda_v1 tie-break.
func caseDeterministicOrder(ctx *caseContext) (*transcript, error) {
	if err := ctx.ws.installResponse("alpha", "alpha-ok.json"); err != nil {
		return nil, err
	}
	if err := ctx.ws.installResponse("beta", "beta-ok.json"); err != nil {
		return nil, err
	}
	if err := ctx.ws.setBlock("beta", false); err != nil {
		return nil, err
	}
	broker, err := ctx.spawn(ctx.ws.federationArguments("fed-ok"))
	if err != nil {
		return nil, err
	}
	record := ctx.newTranscript("deterministic_order")
	check := &checker{}
	first, err := broker.callTool("evidence_search", evidenceQuery(2))
	if err != nil {
		broker.close()
		return nil, err
	}
	ctx.record(record, "fused-order", "evidence_search", evidenceQuery(2), first)
	repeat, err := broker.callTool("evidence_search", evidenceQuery(2))
	broker.close()
	if err != nil {
		return nil, err
	}
	ctx.record(record, "fused-order-repeat", "evidence_search", evidenceQuery(2), repeat)
	fresh, err := ctx.spawn(ctx.ws.federationArguments("fed-ok"))
	if err != nil {
		return nil, err
	}
	acrossProcess, err := fresh.callTool("evidence_search", evidenceQuery(2))
	fresh.close()
	if err != nil {
		return nil, err
	}
	ctx.record(record, "fused-order-fresh-process", "evidence_search", evidenceQuery(2), acrossProcess)

	check.eq("isError", first.IsError, false)
	data := first.Structured
	check.eq("state", data["state"], "ok")
	check.eq("retrieval_state", data["retrieval_state"], "federated_current")
	check.eq("federation_algorithm", data["federation_algorithm"], "bounded_borda_v1")
	check.eq("fusion_window", data["fusion_window"], float64(2))
	results := asList(data["results"])
	check.eq("fused result count", len(results), 2)
	if len(results) == 2 {
		top := asMap(results[0])
		second := asMap(results[1])
		check.eq("rank 1 span (lane tie-break)", asMap(top["evidence"])["span_id"], alphaSpan)
		check.eq("rank 2 span", asMap(second["evidence"])["span_id"], betaSpan)
		check.eq("rank 1 score", top["score"], float64(2))
		check.eq("rank 2 score", second["score"], float64(2))
		check.eq("rank 1 lane", asMap(asList(top["lane_matches"])[0])["lane_id"], "alpha")
		check.eq("rank 2 lane", asMap(asList(second["lane_matches"])[0])["lane_id"], "beta")
	}
	lanes := asList(data["lanes"])
	if len(lanes) == 2 {
		alpha := asMap(lanes[0])
		beta := asMap(lanes[1])
		check.truthy("independent signed generations", alpha["current_generation_id"] != beta["current_generation_id"])
		check.truthy("independent admission sources", alpha["admission_source_id"] != beta["admission_source_id"])
	} else {
		check.truthy("two lane descriptors", false)
	}
	firstBytes := mustNormalize(first, ctx)
	check.truthy("repeat call is byte-identical", bytes.Equal(firstBytes, mustNormalize(repeat, ctx)))
	check.truthy("fresh process is byte-identical", bytes.Equal(firstBytes, mustNormalize(acrossProcess, ctx)))
	return record, check.err()
}

// mustNormalize canonicalizes one call result for byte comparison.
func mustNormalize(result callResult, ctx *caseContext) []byte {
	normalized := normalizeValue(result.Structured, ctx.ws.root, ctx.freeze.Normalization)
	encoded, err := canonicalJSON(normalized)
	if err != nil {
		panic(err)
	}
	return encoded
}

// copySuiteTree clones the suite directory so tamper checks never touch the
// frozen fixtures themselves.
func copySuiteTree(suiteDir string) (string, error) {
	target, err := os.MkdirTemp("", "mcp01-tampered-suite-")
	if err != nil {
		return "", err
	}
	err = filepath.Walk(suiteDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(suiteDir, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if info.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, raw, 0o644)
	})
	if err != nil {
		return "", err
	}
	return target, nil
}

// startHTTPBrokerProcess spawns the broker on a loopback port and waits for
// the authenticated listener to answer.
func (ctx *caseContext) startHTTPBrokerProcess() (*stdioBroker, *httpBroker, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	bind := listener.Addr().String()
	_ = listener.Close()
	process, err := startStdioBroker(ctx.brokerPath, ctx.ws.httpArguments(bind))
	if err != nil {
		return nil, nil, err
	}
	client := &httpBroker{endpoint: "http://" + bind, token: ctx.ws.token}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		response, _, postErr := client.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, "", true)
		if postErr == nil && response.StatusCode == http.StatusOK {
			return process, client, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	process.close()
	return nil, nil, errors.New("HTTP broker did not become ready: " + process.stderr.String())
}

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"mcp01-acceptance","version":"1"}}}`

// runHTTPAuthChecks proves 401-before-any-handler for missing and wrong
// bearer tokens, and that an accepted request creates no transport session.
func (ctx *caseContext) runHTTPAuthChecks(record *transcript, check *checker) error {
	if err := ctx.ws.installResponse("solo", "alpha-ok.json"); err != nil {
		return err
	}
	process, client, err := ctx.startHTTPBrokerProcess()
	if err != nil {
		return err
	}
	defer process.close()

	unauthenticated, unauthenticatedBody, err := client.post(initializeBody, "", false)
	if err != nil {
		return err
	}
	check.eq("unauthenticated status", unauthenticated.StatusCode, http.StatusUnauthorized)
	check.eq("unauthenticated session withheld", unauthenticated.Header.Get("Mcp-Session-Id"), "")
	check.truthy("unauthenticated body discloses no server identity", !strings.Contains(string(unauthenticatedBody), "serverInfo"))

	wrongToken := &httpBroker{endpoint: client.endpoint, token: strings.Repeat("f", len(ctx.ws.token))}
	rejected, rejectedBody, err := wrongToken.post(initializeBody, "", true)
	if err != nil {
		return err
	}
	check.eq("wrong-token status", rejected.StatusCode, http.StatusUnauthorized)
	check.eq("wrong-token session withheld", rejected.Header.Get("Mcp-Session-Id"), "")
	check.truthy("wrong-token body discloses no server identity", !strings.Contains(string(rejectedBody), "serverInfo"))

	accepted, acceptedBody, err := client.post(initializeBody, "", true)
	if err != nil {
		return err
	}
	check.eq("authenticated status", accepted.StatusCode, http.StatusOK)
	check.eq("stateless initialize issues no session", accepted.Header.Get("Mcp-Session-Id"), "")
	check.truthy("authenticated initialize reaches the broker", strings.Contains(string(acceptedBody), "archeion-knowledge-mcp"))
	record.Calls = append(record.Calls, transcriptCall{
		Step: "http-bearer-gate", Tool: "initialize",
		Arguments: map[string]any{"transport": "streamable-http"},
		IsError:   false,
		Result: map[string]any{
			"unauthenticated_status": unauthenticated.StatusCode,
			"wrong_token_status":     rejected.StatusCode,
			"authenticated_status":   accepted.StatusCode,
			"session_id_issued":      false,
		},
	})
	return nil
}

// runHTTPReconnect proves the stateless transport serves a client that
// retained a stale Mcp-Session-Id instead of trapping it in a 404.
func (ctx *caseContext) runHTTPReconnect(record *transcript, check *checker) (callResult, error) {
	if err := ctx.ws.installResponse("solo", "alpha-ok.json"); err != nil {
		return callResult{}, err
	}
	process, client, err := ctx.startHTTPBrokerProcess()
	if err != nil {
		return callResult{}, err
	}
	defer process.close()
	initialized, _, err := client.post(initializeBody, "", true)
	if err != nil {
		return callResult{}, err
	}
	check.eq("http initialize status", initialized.StatusCode, http.StatusOK)
	check.eq("http initialize issues no session", initialized.Header.Get("Mcp-Session-Id"), "")
	result, err := client.callTool("evidence_search", evidenceQuery(0), "expired-session-retained-by-client")
	if err != nil {
		return callResult{}, err
	}
	ctx.record(record, "http-stale-session-served", "evidence_search", evidenceQuery(0), result)
	check.eq("stale-session isError", result.IsError, false)
	check.eq("stale-session state", result.Structured["state"], "ok")
	return result, nil
}
