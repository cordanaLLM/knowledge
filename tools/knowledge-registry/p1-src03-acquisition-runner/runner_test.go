package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type apiFixture struct {
	responses           map[string][]byte
	fileTreeEndpoint    map[string]string
	fileBlobEndpoint    map[string]string
	redirectEndpoint    string
	requireExactHeaders bool
}

type countingTransport struct {
	requests int
}

func (transport *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.requests++
	return nil, errors.New("network is unavailable")
}

func newAPIFixture(t *testing.T, contract acquisitionContract) *apiFixture {
	t.Helper()
	fixture := &apiFixture{responses: map[string][]byte{}, fileTreeEndpoint: map[string]string{}, fileBlobEndpoint: map[string]string{}, requireExactHeaders: true}
	for _, target := range contract.Targets {
		prefix := "/repos/" + target.Repository
		fixture.responses[prefix+"/git/ref/tags/"+target.RequestedTag] = mustJSON(t, gitRef{Ref: "refs/tags/" + target.RequestedTag, Object: gitObject{Type: target.ExpectedRefType, SHA: target.ExpectedRefSHA1}})
		for _, tag := range target.ExpectedTagObjects {
			fixture.responses[prefix+"/git/tags/"+tag.SHA1] = mustJSON(t, gitTag{Tag: tag.Name, SHA: tag.SHA1, Object: gitObject{Type: tag.TargetType, SHA: tag.TargetSHA1}})
		}
		commit := gitCommit{SHA: target.ExpectedCommitSHA1}
		commit.Tree.SHA = target.ExpectedRootTreeSHA1
		fixture.responses[prefix+"/git/commits/"+target.ExpectedCommitSHA1] = mustJSON(t, commit)

		trees := buildFixtureTrees(target)
		for sha, entries := range trees {
			truncated := false
			fixture.responses[prefix+"/git/trees/"+sha] = mustJSON(t, gitTree{SHA: sha, Tree: entries, Truncated: &truncated})
		}
		for _, file := range target.Files {
			rawPath := filepath.Join("..", "..", "knowledge-retrieval", "testdata", "scorer-blind-multidomain-v1", "source-blobs", "sha256", strings.TrimPrefix(file.RawSHA256, "sha256:")[:2], strings.TrimPrefix(file.RawSHA256, "sha256:"))
			raw, err := os.ReadFile(rawPath)
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(raw)) != file.Bytes {
				t.Fatalf("fixture source size mismatch for %s", file.SourceKey)
			}
			size := file.Bytes
			fixture.responses[prefix+"/git/blobs/"+file.GitBlobSHA1] = mustJSON(t, gitBlob{SHA: file.GitBlobSHA1, Size: &size, Encoding: "base64", Content: base64.StdEncoding.EncodeToString(raw)})
			parentSHA := file.ExpectedPathResolution[len(file.ExpectedPathResolution)-1].ParentTreeSHA1
			fixture.fileTreeEndpoint[file.SourceKey] = prefix + "/git/trees/" + parentSHA
			fixture.fileBlobEndpoint[file.SourceKey] = prefix + "/git/blobs/" + file.GitBlobSHA1
		}
	}
	return fixture
}

func buildFixtureTrees(target contractTarget) map[string][]gitTreeEntry {
	result := map[string][]gitTreeEntry{}
	seen := map[string]map[string]gitTreeEntry{}
	for _, file := range target.Files {
		for _, binding := range file.ExpectedPathResolution {
			entry := gitTreeEntry{Path: binding.Segment, Mode: binding.Mode, Type: binding.ObjectType, SHA: binding.ObjectSHA1}
			if binding.Bytes != nil {
				size := *binding.Bytes
				entry.Size = &size
			}
			if seen[binding.ParentTreeSHA1] == nil {
				seen[binding.ParentTreeSHA1] = map[string]gitTreeEntry{}
			}
			if existing, ok := seen[binding.ParentTreeSHA1][binding.Segment]; ok && existing != entry {
				panic("fixture path contract aliases a Git tree child")
			}
			seen[binding.ParentTreeSHA1][binding.Segment] = entry
		}
	}
	for parent, entries := range seen {
		for _, entry := range entries {
			result[parent] = append(result[parent], entry)
		}
		sort.Slice(result[parent], func(left, right int) bool { return result[parent][left].Path < result[parent][right].Path })
	}
	return result
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *apiFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if f.requireExactHeaders && (request.Method != http.MethodGet || request.Header.Get("Accept") != "application/vnd.github+json" || request.Header.Get("X-GitHub-Api-Version") != apiVersion || request.Header.Get("Accept-Encoding") != "identity") {
		http.Error(writer, "headers", http.StatusBadRequest)
		return
	}
	if request.URL.Path == f.redirectEndpoint {
		http.Redirect(writer, request, request.URL.Path+"-redirected", http.StatusFound)
		return
	}
	raw, ok := f.responses[request.URL.Path]
	if !ok {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(raw)
}

func exactFixtureRunner(t *testing.T, fixture *apiFixture, contract acquisitionContract) (*runner, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(fixture)
	value, err := newRunner(server.Client(), server.URL, "", true, contract)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return value, server
}

func TestExactContractDenominator(t *testing.T) {
	contract, raw, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	if contract.ContractID != "source-acquisition-contract:"+contract.ContractPayloadSHA256 || !validSHA256(contract.ContractPayloadSHA256) || !bytes.HasSuffix(raw, []byte{'\n'}) || len(contract.Targets) != 3 {
		t.Fatal("contract identity, serialization, or authority count changed")
	}
	if err := validateContract(contract.contractCore); err != nil {
		t.Fatal(err)
	}
	if got := contract.Bounds.LogicalBytes; got != 512214 {
		t.Fatalf("logical byte denominator = %d", got)
	}
}

func TestContractRejectsAliasingAndWidening(t *testing.T) {
	aliased, err := exactContractCore()
	if err != nil {
		t.Fatal(err)
	}
	aliased.Targets[1].SourceSetID = aliased.Targets[0].SourceSetID
	if err := validateContract(aliased); err == nil || !strings.Contains(err.Error(), "aliases source sets") {
		t.Fatalf("expected source-set alias rejection, got %v", err)
	}
	widened, err := exactContractCore()
	if err != nil {
		t.Fatal(err)
	}
	widened.Targets[0].Files = append(widened.Targets[0].Files, widened.Targets[0].Files[0])
	if err := validateContract(widened); err == nil || !strings.Contains(err.Error(), "two-file scope") {
		t.Fatalf("expected exact-path widening rejection, got %v", err)
	}
}

func TestRunnerProducesDeterministicReceiptAndProposal(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAPIFixture(t, contract)
	firstRunner, firstServer := exactFixtureRunner(t, fixture, contract)
	firstStore, err := newCASStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = firstStore.close() })
	first, err := firstRunner.run(context.Background(), contract, firstStore)
	firstServer.Close()
	if err != nil {
		t.Fatal(err)
	}
	secondRunner, secondServer := exactFixtureRunner(t, fixture, contract)
	defer secondServer.Close()
	secondStore, err := newCASStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondStore.close() })
	second, err := secondRunner.run(context.Background(), contract, secondStore)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.ReceiptBytes, second.ReceiptBytes) || !bytes.Equal(first.ProposalBytes, second.ProposalBytes) || first.Receipt.ReceiptID != second.Receipt.ReceiptID || first.Proposal.ProposalID != second.Proposal.ProposalID {
		t.Fatal("independent acquisitions were not byte-identical")
	}
	if first.Receipt.SchemaVersion != "2.0.0" || first.Proposal.SchemaVersion != "2.0.0" || first.Receipt.AuthorityState != "non_authoritative" || first.Receipt.CompileEligible || first.Proposal.PromoteEligible {
		t.Fatal("v2 output authority boundary widened")
	}
	if first.Receipt.Counts.Targets != 3 || first.Receipt.Counts.Files != 6 || first.Receipt.Counts.LogicalBytes != 512214 || first.Receipt.Counts.UniqueCASObjects != 6 {
		t.Fatalf("unexpected run counts: %+v", first.Receipt.Counts)
	}
	if first.Receipt.Counts.HTTPRequests != expectedHTTPRequests {
		t.Fatalf("HTTP request count = %d, want %d", first.Receipt.Counts.HTTPRequests, expectedHTTPRequests)
	}
	assertContentAddress(t, first.Receipt.ReceiptID, "source-acquisition-receipt:", first.Receipt.ReceiptPayloadSHA256, first.Receipt.receiptCore)
	assertContentAddress(t, first.Proposal.ProposalID, "source-inventory-proposal:", first.Proposal.ProposalPayloadSHA256, first.Proposal.proposalCore)
}

// The adapter's acquisition fixtures are the output of the deterministic run.
// The adapter does not recompute the identifiers in them, so this comparison is
// what refuses an edited fixture.
func TestAdapterAcquisitionFixturesAreTheDeterministicRun(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	fixtureRunner, server := exactFixtureRunner(t, newAPIFixture(t, contract), contract)
	defer server.Close()
	store, err := newCASStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	result, err := fixtureRunner.run(context.Background(), contract, store)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := filepath.Join("..", "..", "knowledge-adapter-v2", "testdata", "acquisition")
	for name, want := range map[string][]byte{"receipt.json": result.ReceiptBytes, "proposal.json": result.ProposalBytes} {
		got, err := os.ReadFile(filepath.Join(fixtures, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the deterministic run", filepath.Join(fixtures, name))
		}
	}
}

func TestReceiptOnlyRecoveryIsOfflineAndPublishesExactProposal(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAPIFixture(t, contract)
	value, server := exactFixtureRunner(t, fixture, contract)
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	first, err := value.run(context.Background(), contract, store)
	server.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.root, filepath.FromSlash(first.ProposalPath))); err != nil {
		t.Fatal(err)
	}

	transport := &countingTransport{}
	offline, err := newRunner(&http.Client{Transport: transport}, "http://127.0.0.1:1", "", true, contract)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := offline.run(context.Background(), contract, store)
	if err != nil {
		t.Fatal(err)
	}
	if transport.requests != 0 || offline.requests != 0 {
		t.Fatalf("receipt-only recovery used the network: transport=%d runner=%d", transport.requests, offline.requests)
	}
	if !bytes.Equal(first.ReceiptBytes, recovered.ReceiptBytes) || !bytes.Equal(first.ProposalBytes, recovered.ProposalBytes) || first.Proposal.ProposalID != recovered.Proposal.ProposalID {
		t.Fatal("receipt-only recovery did not reproduce the exact proposal")
	}
}

func TestProposalWithoutReceiptFailsBeforeNetworkOrWrite(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	proposalID := "source-inventory-proposal:sha256:" + strings.Repeat("a", 64)
	proposalPath, err := store.putProposal(proposalID, []byte("preexisting-conflict\n"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(store.root, filepath.FromSlash(proposalPath)))
	if err != nil {
		t.Fatal(err)
	}
	transport := &countingTransport{}
	value, err := newRunner(&http.Client{Transport: transport}, "http://127.0.0.1:1", "", true, contract)
	if err != nil {
		t.Fatal(err)
	}
	_, err = value.run(context.Background(), contract, store)
	if err == nil || !strings.Contains(err.Error(), "without its predecessor receipt") {
		t.Fatalf("proposal-without-receipt did not fail closed: %v", err)
	}
	if transport.requests != 0 || value.requests != 0 {
		t.Fatalf("proposal-without-receipt used the network: transport=%d runner=%d", transport.requests, value.requests)
	}
	after, err := os.ReadFile(filepath.Join(store.root, filepath.FromSlash(proposalPath)))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("preflight changed existing output: %q, %v", after, err)
	}
	casEntries, err := os.ReadDir(filepath.Join(store.root, "cas", "sha256"))
	if err != nil || len(casEntries) != 0 {
		t.Fatalf("preflight wrote CAS state: %v, %v", casEntries, err)
	}
}

func TestCLIProposalWithoutReceiptFailsBeforeDirectoryInitialization(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	outputRoot := filepath.Join(t.TempDir(), "partial-run")
	proposalDirectory := filepath.Join(outputRoot, "inventory-proposals")
	if err := os.MkdirAll(proposalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	proposalPath := filepath.Join(proposalDirectory, strings.Repeat("a", 64)+".json")
	if err := os.WriteFile(proposalPath, []byte("preexisting-conflict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_TOKEN", "")
	err = runCLI([]string{"--output-root", outputRoot, "--acknowledge-contract-id", contract.ContractID})
	if err == nil || !strings.Contains(err.Error(), "without its predecessor receipt") {
		t.Fatalf("proposal-only partial root did not fail preflight: %v", err)
	}
	for _, absent := range []string{"cas", "receipts"} {
		if _, statErr := os.Stat(filepath.Join(outputRoot, absent)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("preflight initialized %s: %v", absent, statErr)
		}
	}
	if raw, readErr := os.ReadFile(proposalPath); readErr != nil || string(raw) != "preexisting-conflict\n" {
		t.Fatalf("preflight changed proposal-only state: %q, %v", raw, readErr)
	}
}

func TestRecoveryValidatesConflictingProposalBeforeSynchronization(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *casStore, *runResult)
		want   string
	}{
		{name: "wrong name", want: "conflicting or ambiguous", mutate: func(t *testing.T, store *casStore, result *runResult) {
			oldPath := filepath.Join(store.root, filepath.FromSlash(result.ProposalPath))
			newPath := filepath.Join(store.root, "inventory-proposals", strings.Repeat("0", 64)+".json")
			if err := os.Rename(oldPath, newPath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "malformed bytes", want: "decode published inventory proposal", mutate: func(t *testing.T, store *casStore, result *runResult) {
			path := filepath.Join(store.root, filepath.FromSlash(result.ProposalPath))
			if err := os.WriteFile(path, []byte(`{"unterminated":`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			contract, _, err := exactContract()
			if err != nil {
				t.Fatal(err)
			}
			fixture := newAPIFixture(t, contract)
			value, server := exactFixtureRunner(t, fixture, contract)
			store, err := newTestStore(t)
			if err != nil {
				t.Fatal(err)
			}
			result, err := value.run(context.Background(), contract, store)
			server.Close()
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, store, result)

			originalSync := syncOpenedFile
			t.Cleanup(func() { syncOpenedFile = originalSync })
			syncs := 0
			syncOpenedFile = func(file *os.File) error {
				syncs++
				return originalSync(file)
			}
			transport := &countingTransport{}
			offline, err := newRunner(&http.Client{Transport: transport}, "http://127.0.0.1:1", "", true, contract)
			if err != nil {
				t.Fatal(err)
			}
			_, err = offline.run(context.Background(), contract, store)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("conflicting proposal did not fail as %q: %v", test.want, err)
			}
			if syncs != 0 || transport.requests != 0 {
				t.Fatalf("conflict preflight mutated or used network: syncs=%d requests=%d", syncs, transport.requests)
			}
		})
	}
}

func TestInvalidTokenFailsBeforeOutputRootCreation(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	outputRoot := filepath.Join(t.TempDir(), "must-not-exist")
	t.Setenv("GITHUB_TOKEN", "invalid\nheader")
	err = runCLI([]string{"--output-root", outputRoot, "--acknowledge-contract-id", contract.ContractID})
	if err == nil || !strings.Contains(err.Error(), "single-line header") {
		t.Fatalf("invalid token was not rejected: %v", err)
	}
	if _, statErr := os.Stat(outputRoot); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("invalid token created output state: %v", statErr)
	}
}

func TestSemanticValidatorsRejectContentAddressAndLineageForgery(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("contract ID", func(t *testing.T) {
		forged := contract
		forged.ContractID = "source-acquisition-contract:sha256:" + strings.Repeat("0", 64)
		if err := validateMaterializedContract(forged); err == nil || !strings.Contains(err.Error(), "content address") {
			t.Fatalf("forged contract ID was accepted: %v", err)
		}
	})
	t.Run("contract target ID", func(t *testing.T) {
		core, err := exactContractCore()
		if err != nil {
			t.Fatal(err)
		}
		core.Targets[0].TargetID = "source-acquisition-target:sha256:" + strings.Repeat("0", 64)
		if err := validateContract(core); err == nil || !strings.Contains(err.Error(), "target denominator") {
			t.Fatalf("forged contract target ID was accepted: %v", err)
		}
	})
	fixture := newAPIFixture(t, contract)
	value, server := exactFixtureRunner(t, fixture, contract)
	defer server.Close()
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	result, err := value.run(context.Background(), contract, store)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("receipt ID", func(t *testing.T) {
		forged := cloneReceipt(t, result.Receipt)
		forged.ReceiptID = "source-acquisition-receipt:sha256:" + strings.Repeat("0", 64)
		raw, err := documentJSON(forged)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateReceiptDocument(contract, forged, raw); err == nil || !strings.Contains(err.Error(), "content address") {
			t.Fatalf("forged receipt ID was accepted: %v", err)
		}
	})
	t.Run("receipt payload", func(t *testing.T) {
		forged := cloneReceipt(t, result.Receipt)
		forged.ReceiptPayloadSHA256 = "sha256:" + strings.Repeat("0", 64)
		raw, err := documentJSON(forged)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateReceiptDocument(contract, forged, raw); err == nil || !strings.Contains(err.Error(), "content address") {
			t.Fatalf("forged receipt payload hash was accepted: %v", err)
		}
	})
	for _, test := range []struct {
		name   string
		mutate func(*receipt)
		want   string
	}{
		{name: "CAS path", mutate: func(value *receipt) {
			value.Targets[0].Files[0].CASPath = value.Targets[0].Files[1].CASPath
		}, want: "inventory file"},
		{name: "path chain", mutate: func(value *receipt) {
			value.Targets[0].Files[0].PathResolution[0].ObjectSHA1 = strings.Repeat("0", 40)
		}, want: "path resolution"},
		{name: "runner execution manifest", mutate: func(value *receipt) {
			value.Runner.ExecutionManifestID = "source-acquisition-execution-manifest:sha256:" + strings.Repeat("0", 64)
		}, want: "execution lineage"},
		{name: "receipt target ID", mutate: func(value *receipt) {
			value.Targets[0].TargetID = "source-acquisition-target:sha256:" + strings.Repeat("0", 64)
		}, want: "inventory authority"},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := cloneReceipt(t, result.Receipt)
			test.mutate(&forged)
			forged, raw, err := materializeReceipt(forged.receiptCore)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateReceiptDocument(contract, forged, raw); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("semantically forged receipt was accepted: %v", err)
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(*inventoryProposal)
	}{
		{name: "receipt binding", mutate: func(value *inventoryProposal) {
			value.AcquisitionReceipt.ReceiptID = "source-acquisition-receipt:sha256:" + strings.Repeat("0", 64)
		}},
		{name: "receipt projection", mutate: func(value *inventoryProposal) {
			value.Targets[0].Counts.Trees++
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := cloneProposal(t, result.Proposal)
			test.mutate(&forged)
			forged, raw, err := materializeProposal(forged.proposalCore)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateProposalDocument(contract, result.Receipt, forged, raw); err == nil || !strings.Contains(err.Error(), "exactly project") {
				t.Fatalf("semantically forged proposal was accepted: %v", err)
			}
		})
	}
	t.Run("proposal ID", func(t *testing.T) {
		forged := cloneProposal(t, result.Proposal)
		forged.ProposalID = "source-inventory-proposal:sha256:" + strings.Repeat("0", 64)
		raw, err := documentJSON(forged)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateProposalDocument(contract, result.Receipt, forged, raw); err == nil || !strings.Contains(err.Error(), "content address") {
			t.Fatalf("forged proposal ID was accepted: %v", err)
		}
	})
	t.Run("proposal payload", func(t *testing.T) {
		forged := cloneProposal(t, result.Proposal)
		forged.ProposalPayloadSHA256 = "sha256:" + strings.Repeat("0", 64)
		raw, err := documentJSON(forged)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateProposalDocument(contract, result.Receipt, forged, raw); err == nil || !strings.Contains(err.Error(), "content address") {
			t.Fatalf("forged proposal payload hash was accepted: %v", err)
		}
	})
}

func cloneReceipt(t *testing.T, value receipt) receipt {
	t.Helper()
	raw, err := documentJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone receipt
	if err := unmarshalStrictJSON(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func cloneProposal(t *testing.T, value inventoryProposal) inventoryProposal {
	t.Helper()
	raw, err := documentJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone inventoryProposal
	if err := unmarshalStrictJSON(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestValidateInventoriesRejectsResolutionAndCountDrift(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAPIFixture(t, contract)
	value, server := exactFixtureRunner(t, fixture, contract)
	defer server.Close()
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	result, err := value.run(context.Background(), contract, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInventories(contract, result.Receipt.Targets); err != nil {
		t.Fatalf("valid inventory rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]targetInventory)
		want   string
	}{
		{name: "tag chain", mutate: func(values []targetInventory) {
			values[0].TagResolution.InitialObjectSHA1 = strings.Repeat("0", 40)
		}, want: "tag resolution"},
		{name: "path root", mutate: func(values []targetInventory) {
			values[0].Files[0].PathResolution[0].ParentTreeSHA1 = strings.Repeat("0", 40)
		}, want: "disconnected"},
		{name: "intermediate type", mutate: func(values []targetInventory) {
			values[0].Files[0].PathResolution[0].ObjectType = "blob"
		}, want: "exact tree"},
		{name: "terminal blob", mutate: func(values []targetInventory) {
			bindings := values[0].Files[0].PathResolution
			bindings[len(bindings)-1].ObjectSHA1 = strings.Repeat("0", 40)
		}, want: "exact blob"},
		{name: "target counts", mutate: func(values []targetInventory) {
			values[0].Counts.Trees++
		}, want: "target counts"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inventories := cloneInventories(t, result.Receipt.Targets)
			test.mutate(inventories)
			if err := validateInventories(contract, inventories); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wanted %q rejection, got %v", test.want, err)
			}
		})
	}
}

func cloneInventories(t *testing.T, values []targetInventory) []targetInventory {
	t.Helper()
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	var clone []targetInventory
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func assertContentAddress(t *testing.T, id, prefix, claim string, core any) {
	t.Helper()
	raw, err := canonicalJSON(core)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(digest[:])
	if claim != want || id != prefix+want {
		t.Fatalf("invalid content address %s / %s, want %s", id, claim, want)
	}
}

func TestRunnerFailsClosedOnDriftRedirectPathSizeAndBlob(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	first := contract.Targets[0]
	firstFile := first.Files[0]
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *apiFixture)
		want   string
	}{
		{
			name: "tag drift",
			mutate: func(t *testing.T, fixture *apiFixture) {
				endpoint := "/repos/" + first.Repository + "/git/ref/tags/" + first.RequestedTag
				fixture.responses[endpoint] = mustJSON(t, gitRef{Ref: "refs/tags/" + first.RequestedTag, Object: gitObject{Type: first.ExpectedRefType, SHA: strings.Repeat("0", 40)}})
			},
			want: "tag ref drifted",
		},
		{
			name: "redirect",
			mutate: func(_ *testing.T, fixture *apiFixture) {
				fixture.redirectEndpoint = "/repos/" + first.Repository + "/git/ref/tags/" + first.RequestedTag
			},
			want: "redirects are forbidden",
		},
		{
			name: "path mismatch",
			mutate: func(t *testing.T, fixture *apiFixture) {
				endpoint := fixture.fileTreeEndpoint[firstFile.SourceKey]
				var tree gitTree
				if err := json.Unmarshal(fixture.responses[endpoint], &tree); err != nil {
					t.Fatal(err)
				}
				tree.Tree[0].Path = "wrong-name.rst"
				fixture.responses[endpoint] = mustJSON(t, tree)
			},
			want: "no exact requested child",
		},
		{
			name: "size mismatch",
			mutate: func(t *testing.T, fixture *apiFixture) {
				endpoint := fixture.fileTreeEndpoint[firstFile.SourceKey]
				var tree gitTree
				if err := json.Unmarshal(fixture.responses[endpoint], &tree); err != nil {
					t.Fatal(err)
				}
				for index := range tree.Tree {
					if tree.Tree[index].Path == filepath.Base(firstFile.Path) {
						wrong := firstFile.Bytes + 1
						tree.Tree[index].Size = &wrong
					}
				}
				fixture.responses[endpoint] = mustJSON(t, tree)
			},
			want: "size drifted",
		},
		{
			name: "blob mismatch",
			mutate: func(t *testing.T, fixture *apiFixture) {
				endpoint := fixture.fileBlobEndpoint[firstFile.SourceKey]
				var blob gitBlob
				if err := json.Unmarshal(fixture.responses[endpoint], &blob); err != nil {
					t.Fatal(err)
				}
				raw, err := base64.StdEncoding.DecodeString(blob.Content)
				if err != nil {
					t.Fatal(err)
				}
				raw[0] ^= 0xff
				blob.Content = base64.StdEncoding.EncodeToString(raw)
				fixture.responses[endpoint] = mustJSON(t, blob)
			},
			want: "does not reproduce",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAPIFixture(t, contract)
			test.mutate(t, fixture)
			value, server := exactFixtureRunner(t, fixture, contract)
			defer server.Close()
			store, err := newCASStore(filepath.Join(t.TempDir(), "run"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.close() })
			_, err = value.run(context.Background(), contract, store)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wanted %q failure, got %v", test.want, err)
			}
		})
	}
}

func TestStrictJSONRejectsDuplicateKeys(t *testing.T) {
	if _, err := parseStrictJSON([]byte(`{"sha":"a","sha":"b"}`)); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("unexpected duplicate-key result: %v", err)
	}
}

func TestCanonicalJSONRejectsInvalidProgrammaticUTF8(t *testing.T) {
	invalid := string([]byte{0xff})
	for _, value := range []any{
		map[string]any{"value": invalid},
		map[string]any{invalid: "value"},
		struct {
			Value string `json:"value"`
		}{Value: invalid},
		acquisitionContract{contractCore: contractCore{Schema: invalid}},
	} {
		if _, err := canonicalJSON(value); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
			t.Fatalf("invalid programmatic UTF-8 was accepted: %v", err)
		}
	}
}

func TestSharedCanonicalJSONConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "canonical-json", "v1", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Values []struct {
			ID        string            `json:"id"`
			Value     json.RawMessage   `json:"value"`
			Canonical map[string]string `json:"canonical"`
		} `json:"values"`
		RejectRaw []struct {
			ID        string `json:"id"`
			RawUTF8   string `json:"raw_utf8"`
			RawBase64 string `json:"raw_base64"`
		} `json:"reject_raw"`
		RejectNoncanonical []struct {
			ID        string            `json:"id"`
			RawUTF8   string            `json:"raw_utf8"`
			Canonical map[string]string `json:"canonical"`
		} `json:"reject_noncanonical"`
		Bounds struct {
			NestedArrays []struct {
				ID       string            `json:"id"`
				Levels   int               `json:"levels"`
				Expected map[string]string `json:"expected"`
			} `json:"nested_arrays"`
		} `json:"bounds"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.Values {
		t.Run("canonical/"+vector.ID, func(t *testing.T) {
			value, err := parseStrictJSON(vector.Value)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := canonicalJSON(value)
			if err != nil {
				t.Fatal(err)
			}
			if string(actual) != vector.Canonical[canonicalProfile] {
				t.Fatalf("canonical bytes = %q, want %q", actual, vector.Canonical[canonicalProfile])
			}
		})
	}
	for _, vector := range vectors.RejectRaw {
		t.Run("reject/"+vector.ID, func(t *testing.T) {
			raw := []byte(vector.RawUTF8)
			if vector.RawBase64 != "" {
				var err error
				raw, err = base64.StdEncoding.DecodeString(vector.RawBase64)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := parseStrictJSON(raw); err == nil {
				t.Fatal("unsafe shared JSON vector was accepted")
			}
		})
	}
	for _, vector := range vectors.RejectNoncanonical {
		t.Run("noncanonical/"+vector.ID, func(t *testing.T) {
			parsed, err := parseStrictJSON([]byte(vector.RawUTF8))
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalJSON(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(canonical, []byte(vector.RawUTF8)) {
				t.Fatal("noncanonical shared vector reproduced unchanged")
			}
			if want := vector.Canonical[canonicalProfile]; want != "" && string(canonical) != want {
				t.Fatalf("recanonicalized bytes = %q, want %q", canonical, want)
			}
		})
	}
	for _, vector := range vectors.Bounds.NestedArrays {
		t.Run("depth/"+vector.ID, func(t *testing.T) {
			raw := []byte(strings.Repeat("[", vector.Levels) + "0" + strings.Repeat("]", vector.Levels))
			_, err := parseStrictJSON(raw)
			if vector.Expected[canonicalProfile] == "accept" && err != nil {
				t.Fatalf("expected accept: %v", err)
			}
			if vector.Expected[canonicalProfile] == "reject" && err == nil {
				t.Fatal("expected depth rejection")
			}
		})
	}
}

func verifyExecutionArtifact(tb testingTB, artifact executionArtifact, repositoryRoot, dataRoot string) {
	tb.Helper()
	path := filepath.Join(repositoryRoot, filepath.FromSlash(artifact.LogicalPath))
	if strings.HasPrefix(artifact.LogicalPath, "knowledge/registry/") {
		path = filepath.Join(dataRoot, filepath.FromSlash(artifact.LogicalPath))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if strings.HasPrefix(artifact.LogicalPath, "knowledge/registry/") {
			tb.Fatalf("missing data root file %s: %v", path, err)
		} else {
			tb.Fatalf("missing repository file %s: %v", path, err)
		}
		return
	}
	digest := sha256.Sum256(raw)
	if got := "sha256:" + hex.EncodeToString(digest[:]); got != artifact.SHA256 || int64(len(raw)) != artifact.Bytes {
		tb.Fatalf("execution artifact drifted: %s = %s/%d, want %s/%d", artifact.LogicalPath, got, len(raw), artifact.SHA256, artifact.Bytes)
		return
	}
}

func TestExecutionManifestBindsExactRepositoryBytes(t *testing.T) {
	manifest, err := exactExecutionManifest()
	if err != nil {
		t.Fatal(err)
	}
	dataRoot := knowledgeDataRoot(t, "execution manifest exact repository bytes",
		"knowledge/registry/schemas/source-acquisition-contract-v2.schema.json")
	repositoryRoot := filepath.Join("..", "..", "..")
	for _, artifact := range manifest.Artifacts {
		verifyExecutionArtifact(t, artifact, repositoryRoot, dataRoot)
	}
	gate, err := exactExecutionGateBinding()
	if err != nil {
		t.Fatal(err)
	}
	if gate.Verified || gate.PredecessorEligible || !gate.ExternalVerificationRequired {
		t.Fatalf("execution verifier gate widened: %+v", gate)
	}
	for _, test := range []struct {
		name   string
		mutate func(*executionManifestCore)
	}{
		{name: "toolchain", mutate: func(core *executionManifestCore) { core.Toolchain.GOOS = "forged" }},
		{name: "GOROOT closure", mutate: func(core *executionManifestCore) {
			core.Dependencies.GOROOTTreeSHA256 = "sha256:" + strings.Repeat("0", 64)
		}},
		{name: "artifact denominator", mutate: func(core *executionManifestCore) { core.Artifacts = core.Artifacts[:len(core.Artifacts)-1] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			core := manifest.executionManifestCore
			core.Artifacts = append([]executionArtifact(nil), core.Artifacts...)
			test.mutate(&core)
			if err := validateExecutionManifestCore(core); err == nil {
				t.Fatal("execution manifest scope drift was accepted")
			}
		})
	}
}

func syntheticPlantedArtifact() (executionArtifact, []byte) {
	content := []byte("synthetic planted artifact payload\n")
	digest := sha256.Sum256(content)
	return executionArtifact{
		LogicalPath: "tools/planted/absent.txt",
		Role:        "planted-test",
		SHA256:      "sha256:" + hex.EncodeToString(digest[:]),
		Bytes:       int64(len(content)),
	}, content
}

func TestExecutionManifestPlantedRepositoryArtifactMissingFails(t *testing.T) {
	artifact, content := syntheticPlantedArtifact()
	tempRepoRoot := t.TempDir()
	tempDataRoot := t.TempDir()
	dataCopyPath := filepath.Join(tempDataRoot, filepath.FromSlash(artifact.LogicalPath))
	if err := os.MkdirAll(filepath.Dir(dataCopyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataCopyPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	spy := &spyTB{}
	verifyExecutionArtifact(spy, artifact, tempRepoRoot, tempDataRoot)
	if !spy.failed {
		t.Fatalf("expected missing repository artifact %s to fail, but read from data root succeeded", artifact.LogicalPath)
	}
	expectedRepoPath := filepath.Join(tempRepoRoot, filepath.FromSlash(artifact.LogicalPath))
	if !strings.Contains(spy.message, expectedRepoPath) {
		t.Fatalf("expected failure message %q to name repository path %s", spy.message, expectedRepoPath)
	}
}

func TestExecutionManifestPlantedRepositoryArtifactPresentOrDrifted(t *testing.T) {
	artifact, content := syntheticPlantedArtifact()
	tempRepoRoot := t.TempDir()
	tempDataRoot := t.TempDir()
	repoPath := filepath.Join(tempRepoRoot, filepath.FromSlash(artifact.LogicalPath))
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repoPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	spyPass := &spyTB{}
	verifyExecutionArtifact(spyPass, artifact, tempRepoRoot, tempDataRoot)
	if spyPass.failed {
		t.Fatalf("expected matching repository artifact to pass, got: %s", spyPass.message)
	}

	corrupted := append([]byte(nil), content...)
	corrupted[0] ^= 0xff
	if err := os.WriteFile(repoPath, corrupted, 0o644); err != nil {
		t.Fatal(err)
	}

	spyDrift := &spyTB{}
	verifyExecutionArtifact(spyDrift, artifact, tempRepoRoot, tempDataRoot)
	if !spyDrift.failed {
		t.Fatal("expected wrong digest to fail with drift line")
	}
	if !strings.Contains(spyDrift.message, "execution artifact drifted:") {
		t.Fatalf("expected failure message to report drift, got: %s", spyDrift.message)
	}
}

func TestRunnerContractDigestIsDeterministicAndManifestBound(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := runnerContractDigest(contract)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := runnerContractDigest(contract)
	if err != nil {
		t.Fatal(err)
	}
	if actual != replay || !validSHA256(actual) {
		t.Fatalf("runner contract digest is unstable or malformed: %s / %s", actual, replay)
	}
}

func TestEmitSchemaValidationFixtures(t *testing.T) {
	outputRoot := os.Getenv("P1_SRC03_TEST_OUTPUT_ROOT")
	if outputRoot == "" {
		t.Skip("set P1_SRC03_TEST_OUTPUT_ROOT for schema integration fixtures")
	}
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAPIFixture(t, contract)
	value, server := exactFixtureRunner(t, fixture, contract)
	defer server.Close()
	store, err := newCASStore(outputRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	if _, err := value.run(context.Background(), contract, store); err != nil {
		t.Fatal(err)
	}
}

func verifyRunnerIdentities(t *testing.T) {
	t.Helper()
	identities := []string{
		"source-acquisition-plan:sha256:7b06d690d2edfe08e1fd05060116b3ca08a2a8f82763976f4d4fe1232c844aad",
		"accepted-record-artifact-bundle:sha256:61310bc368840c0202b0bd6e6d828c140aba26b7a389922d9b1fdbb836aecba6",
		"sha256:6306df08e525472da822d10477ea12a9ec3929d14d9d322f842ac88b76401fdb",
	}
	paths := []string{"../source-acquisition-runner/contract.go", "../source-acquisition-runner/github.go", "../source-acquisition-runner/README.md"}
	for _, identity := range identities {
		found := false
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			found = found || bytes.Contains(raw, []byte(identity))
		}
		if !found {
			t.Fatalf("P1-SRC-02 frozen identity disappeared: %s", identity)
		}
	}
}

func TestP1SRC02RunnerAndSchemasRemainByteIdentical(t *testing.T) {
	runnerFiles := map[string]string{
		"../source-acquisition-runner/README.md":      "f7da4d8a2f555970203d33d5750cef97c2dc383c77867bf7d5aa333ce2c8646c",
		"../source-acquisition-runner/cas.go":         "93721cb78aa49acc8377a209f3df6b6368056c276744dc49e0338f5887ddea75",
		"../source-acquisition-runner/contract.go":    "aef2405575f8fee962611f8fee95a852483337fd75636afc71d81f0969f2ff15",
		"../source-acquisition-runner/github.go":      "37c48cfbe1efe4932ee126271eb8958fd8f138714f02710d8afa648e6e2e80e3",
		"../source-acquisition-runner/go.mod":         "793c7f899940cc686f170ff89215d9b8eee48f4ebfaf793726b70b1be10c32de",
		"../source-acquisition-runner/main.go":        "a99cd8e28f21f325fd2ef057169e477a8ff30a04302726e0be3470f1e2335127",
		"../source-acquisition-runner/runner_test.go": "de66639d35f46611ceff59b4a9a01f7883c90ec29c316d8b47cf38d16a062fe8",
	}
	for path, want := range runnerFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		if got := hex.EncodeToString(digest[:]); got != want {
			t.Fatalf("P1-SRC-02 frozen artifact changed: %s = %s, want %s", path, got, want)
		}
	}
	verifyRunnerIdentities(t)

	schemaFiles := map[string]string{
		"knowledge/registry/schemas/source-acquisition-receipt.schema.json":       "ed1577e9741674b0a5ad036b949b811293b82579c635c6c63bc5e561eab1eeb1",
		"knowledge/registry/schemas/source-inventory-proposal.schema.json":        "a9197f0a7ac704f92650354153e35ad90734b99feaa99ebb7bb38123932f12ac",
		"knowledge/registry/schemas/source-acquisition-output-common.schema.json": "0a6b54bfab2af8ec7400de5b439d34d6f9f05c8d914deb479585dbe73ee92549",
		"knowledge/registry/schemas/source-acquisition-plan.schema.json":          "a89767e5b9689da4242bfbc2d22160baad204f6596ad61aab6b41fd00c50358d",
	}
	t.Run("schemas", func(t *testing.T) {
		dataRoot := knowledgeDataRoot(t, "P1-SRC-02 schema byte identity",
			"knowledge/registry/schemas/source-acquisition-receipt.schema.json")
		for rel, want := range schemaFiles {
			path := filepath.Join(dataRoot, filepath.FromSlash(rel))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read schema %s: %v", path, err)
			}
			digest := sha256.Sum256(raw)
			if got := hex.EncodeToString(digest[:]); got != want {
				t.Fatalf("P1-SRC-02 frozen schema changed: %s = %s, want %s", path, got, want)
			}
		}
	})
}

func TestGetJSONRejectsRepositoryOutsideContract(t *testing.T) {
	contract, _, err := exactContract()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAPIFixture(t, contract)
	value, server := exactFixtureRunner(t, fixture, contract)
	defer server.Close()
	var response gitRef
	err = value.getJSON(context.Background(), "someone/else", "/git/ref/tags/v1", &response)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("unexpected repository-boundary result: %v", err)
	}
}

func TestCASRejectsSymlinkAndConflictingReplay(t *testing.T) {
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("cas-object")
	digest := sha256.Sum256(raw)
	rawSHA := "sha256:" + hex.EncodeToString(digest[:])
	hexDigest := strings.TrimPrefix(rawSHA, "sha256:")
	directory, err := store.ensureDirectory(filepath.Join("cas", "sha256", hexDigest[:2]))
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(directory, hexDigest)
	if err := os.Symlink("/etc/passwd", final); err != nil {
		t.Fatal(err)
	}
	if _, err := store.putBlob(rawSHA, raw); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("CAS symlink was not rejected: %v", err)
	}

	conflictingStore, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	conflictingDirectory, err := conflictingStore.ensureDirectory(filepath.Join("cas", "sha256", hexDigest[:2]))
	if err != nil {
		t.Fatal(err)
	}
	conflictingFinal := filepath.Join(conflictingDirectory, hexDigest)
	incomplete := []byte("bad-object")
	if err := os.WriteFile(conflictingFinal, incomplete, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := conflictingStore.putBlob(rawSHA, raw); err == nil || !strings.Contains(err.Error(), "different bytes") {
		t.Fatalf("conflicting CAS replay was not rejected: %v", err)
	}
	if existing, err := os.ReadFile(conflictingFinal); err != nil || !bytes.Equal(existing, incomplete) {
		t.Fatalf("conflicting path was altered: %q, %v", existing, err)
	}
}

func TestCASFullBytesBeforeFsyncFailureAreDurablyRehabilitated(t *testing.T) {
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("full-before-fsync")
	digest := sha256.Sum256(raw)
	rawSHA := "sha256:" + hex.EncodeToString(digest[:])
	hexDigest := strings.TrimPrefix(rawSHA, "sha256:")
	if _, err := store.ensureDirectory(filepath.Join("cas", "sha256", hexDigest[:2])); err != nil {
		t.Fatal(err)
	}
	originalSync := syncOpenedFile
	t.Cleanup(func() { syncOpenedFile = originalSync })
	failed := false
	syncOpenedFile = func(file *os.File) error {
		info, statErr := file.Stat()
		if statErr != nil {
			return statErr
		}
		if info.Mode().IsRegular() && !failed {
			failed = true
			return errors.New("injected file fsync failure")
		}
		return originalSync(file)
	}
	if _, err := store.putBlob(rawSHA, raw); err == nil || !strings.Contains(err.Error(), "injected file fsync failure") {
		t.Fatalf("wanted injected fsync failure, got %v", err)
	}
	regularSyncs := 0
	directorySyncs := 0
	syncOpenedFile = func(file *os.File) error {
		info, statErr := file.Stat()
		if statErr != nil {
			return statErr
		}
		if info.Mode().IsRegular() {
			regularSyncs++
		} else if info.IsDir() {
			directorySyncs++
		}
		return originalSync(file)
	}
	if _, err := store.putBlob(rawSHA, raw); err != nil {
		t.Fatalf("rehabilitate exact uncertain bytes: %v", err)
	}
	if regularSyncs < 1 || directorySyncs < 1 {
		t.Fatalf("retry did not fsync file and directory: files=%d dirs=%d", regularSyncs, directorySyncs)
	}
}

func TestCASParentReplacementFailsClosedAndRetainsWriterInode(t *testing.T) {
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("anchored-parent")
	digest := sha256.Sum256(raw)
	rawSHA := "sha256:" + hex.EncodeToString(digest[:])
	hexDigest := strings.TrimPrefix(rawSHA, "sha256:")
	directory, err := store.ensureDirectory(filepath.Join("cas", "sha256", hexDigest[:2]))
	if err != nil {
		t.Fatal(err)
	}
	moved := directory + "-moved"
	originalSync := syncOpenedFile
	t.Cleanup(func() { syncOpenedFile = originalSync })
	swapped := false
	syncOpenedFile = func(file *os.File) error {
		if err := originalSync(file); err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && !swapped {
			swapped = true
			if err := os.Rename(directory, moved); err != nil {
				return err
			}
			if err := os.Mkdir(directory, 0o700); err != nil {
				return err
			}
		}
		return nil
	}
	if _, err := store.putBlob(rawSHA, raw); err == nil || !strings.Contains(err.Error(), "parent changed") {
		t.Fatalf("parent replacement did not fail closed: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(moved, hexDigest)); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("writer-owned bytes were not retained: %q, %v", got, err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("replacement directory received output: %v, %v", entries, err)
	}
}

func TestCASRejectsUnsafeExistingObjectsAndRoot(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(string) error
		want string
	}{
		{name: "group readable", set: func(path string) error { return os.Chmod(path, 0o640) }, want: "accessible by group or world"},
		{name: "hard linked", set: func(path string) error { return os.Link(path, path+".alias") }, want: "exactly one filesystem link"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := newTestStore(t)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte("private-single-link-object")
			digest := sha256.Sum256(raw)
			rawSHA := "sha256:" + hex.EncodeToString(digest[:])
			hexDigest := strings.TrimPrefix(rawSHA, "sha256:")
			directory, err := store.ensureDirectory(filepath.Join("cas", "sha256", hexDigest[:2]))
			if err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(directory, hexDigest)
			if err := os.WriteFile(final, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := test.set(final); err != nil {
				t.Fatal(err)
			}
			if _, err := store.putBlob(rawSHA, raw); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wanted %q rejection, got %v", test.want, err)
			}
		})
	}

	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newCASStore(root); err == nil || !strings.Contains(err.Error(), "accessible by group or world") {
		t.Fatalf("non-private output root was accepted: %v", err)
	}
}

func TestPublishedRunSetRequiresExactSingletons(t *testing.T) {
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	receiptID := "source-acquisition-receipt:sha256:" + strings.Repeat("a", 64)
	proposalID := "source-inventory-proposal:sha256:" + strings.Repeat("b", 64)
	receiptRaw := []byte("receipt\n")
	proposalRaw := []byte("proposal\n")
	receiptPath, err := store.putReceipt(receiptID, receiptRaw)
	if err != nil {
		t.Fatal(err)
	}
	proposalPath, err := store.putProposal(proposalID, proposalRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.verifyRunSet(receiptPath, receiptRaw, proposalPath, proposalRaw); err != nil {
		t.Fatalf("exact singleton set was rejected: %v", err)
	}
	extra := filepath.Join(store.root, "receipts", strings.Repeat("c", 64)+".json")
	if err := os.WriteFile(extra, []byte("ambiguous\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyRunSet(receiptPath, receiptRaw, proposalPath, proposalRaw); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous receipt set was accepted: %v", err)
	}
}

func newTestStore(t *testing.T) (*casStore, error) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "run")
	store, err := newCASStore(root)
	if err == nil {
		t.Cleanup(func() { _ = store.close() })
	}
	return store, err
}

func Example_contractID() {
	contract, _, _ := exactContract()
	fmt.Println(contract.ContractID)
	// Output: source-acquisition-contract:sha256:e2f0091cfad38a5a602cf2e3a1e4aed5c1b1b5d63a1798c127f8fb3be44c923a
}
