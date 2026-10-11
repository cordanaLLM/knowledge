package main

// End-to-end acquisition over a deterministic httptest Git-object tree. The
// fixture serves the exact tree/commit/ref/blob responses a hand-built contract
// declares, so the runner's full fail-closed data plane (redirect ban,
// non-recursive tree walk, git blob SHA-1 reconstruction, CAS commit, receipt +
// inventory-proposal projection) runs against real bytes. Both ref kinds are
// exercised: an annotated-tag target (unchanged) and a branch-HEAD target.

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type apiFixture struct {
	responses           map[string][]byte
	redirectEndpoint    string
	requireExactHeaders bool
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

func mustJSONFixture(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func gitBlobSHA1(content []byte) string {
	digest := sha1.Sum(append([]byte("blob "+strconv.Itoa(len(content))+"\x00"), content...))
	return hex.EncodeToString(digest[:])
}

func labelSHA1(label string) string {
	digest := sha1.Sum([]byte(label))
	return hex.EncodeToString(digest[:])
}

type fixtureFile struct {
	sourceKey string
	path      string
	mode      string
	content   []byte
}

type treeNode struct {
	children map[string]*treeNode
	blobs    map[string][]byte
	modes    map[string]string
}

func newTreeNode() *treeNode {
	return &treeNode{children: map[string]*treeNode{}, blobs: map[string][]byte{}, modes: map[string]string{}}
}

func (n *treeNode) insert(segments []string, mode string, content []byte) {
	if len(segments) == 1 {
		n.blobs[segments[0]] = content
		n.modes[segments[0]] = mode
		return
	}
	child, ok := n.children[segments[0]]
	if !ok {
		child = newTreeNode()
		n.children[segments[0]] = child
	}
	child.insert(segments[1:], mode, content)
}

// emit assigns synthetic tree SHAs (labelSHA1("tree:"+dirPath)) and registers
// every tree/blob response; pathResolutionFor recomputes the same identities.
func (n *treeNode) emit(prefix, dirPath string, fixture *apiFixture, t *testing.T) string {
	treeSHA := labelSHA1("tree:" + dirPath)
	entries := make([]gitTreeEntry, 0, len(n.children)+len(n.blobs))
	for name, child := range n.children {
		childSHA := child.emit(prefix, dirPath+"/"+name, fixture, t)
		entries = append(entries, gitTreeEntry{Path: name, Mode: "040000", Type: "tree", SHA: childSHA})
	}
	for name, content := range n.blobs {
		blobSHA := gitBlobSHA1(content)
		size := int64(len(content))
		entries = append(entries, gitTreeEntry{Path: name, Mode: n.modes[name], Type: "blob", SHA: blobSHA, Size: &size})
		fixture.responses[prefix+"/git/blobs/"+blobSHA] = mustJSONFixture(t, gitBlob{SHA: blobSHA, Size: &size, Encoding: "base64", Content: base64.StdEncoding.EncodeToString(content)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	truncated := false
	fixture.responses[prefix+"/git/trees/"+treeSHA] = mustJSONFixture(t, gitTree{SHA: treeSHA, Tree: entries, Truncated: &truncated})
	return treeSHA
}

// pathResolutionFor reconstructs the tree-chain bindings emit produced for one
// file path, so the contract matches the served tree exactly.
func pathResolutionFor(path, mode string, content []byte) []pathBinding {
	segments := strings.Split(path, "/")
	bindings := make([]pathBinding, 0, len(segments))
	dirPath := ""
	for index, segment := range segments {
		parent := labelSHA1("tree:" + dirPath)
		if index < len(segments)-1 {
			childDir := dirPath + "/" + segment
			bindings = append(bindings, pathBinding{ParentTreeSHA1: parent, Segment: segment, ObjectType: "tree", Mode: "040000", ObjectSHA1: labelSHA1("tree:" + childDir)})
			dirPath = childDir
			continue
		}
		size := int64(len(content))
		bindings = append(bindings, pathBinding{ParentTreeSHA1: parent, Segment: segment, ObjectType: "blob", Mode: mode, ObjectSHA1: gitBlobSHA1(content), Bytes: &size})
	}
	return bindings
}

func runnerSampleFiles() []fixtureFile {
	return []fixtureFile{
		{sourceKey: "guide", path: "docs/network/guide.md", mode: "100644", content: []byte("# Guide\n\nExact bytes for the guide.\n")},
		{sourceKey: "lib", path: "src/lib.go", mode: "100644", content: []byte("package lib\n\nfunc Answer() int { return 42 }\n")},
		{sourceKey: "tool", path: "src/cmd/tool.sh", mode: "100755", content: []byte("#!/bin/sh\necho tool\n")},
	}
}

// buildRunnerContract builds a fixture and the matching contract core for one
// target. refKind "" is an annotated tag; "branch" is a branch-HEAD target.
func buildRunnerContract(t *testing.T, repository, refKind, refName string, files []fixtureFile) (*apiFixture, contractCore) {
	t.Helper()
	fixture := &apiFixture{responses: map[string][]byte{}, requireExactHeaders: true}
	prefix := "/repos/" + repository
	root := newTreeNode()
	for _, file := range files {
		root.insert(strings.Split(file.path, "/"), file.mode, file.content)
	}
	rootSHA := root.emit(prefix, "", fixture, t)
	commitSHA := labelSHA1("commit:" + repository + ":" + refName)
	commit := gitCommit{SHA: commitSHA}
	commit.Tree.SHA = rootSHA
	fixture.responses[prefix+"/git/commits/"+commitSHA] = mustJSONFixture(t, commit)

	gate, err := exactExecutionGateBinding()
	if err != nil {
		t.Fatalf("execution gate binding: %v", err)
	}

	var refType, refSHA string
	var chain []expectedTagObject
	if refKind == "branch" {
		fixture.responses[prefix+"/git/ref/heads/"+refName] = mustJSONFixture(t, gitRef{Ref: "refs/heads/" + refName, Object: gitObject{Type: "commit", SHA: commitSHA}})
		refType, refSHA, chain = "commit", commitSHA, []expectedTagObject{}
	} else {
		tagSHA := labelSHA1("tag:" + repository + ":" + refName)
		fixture.responses[prefix+"/git/ref/tags/"+refName] = mustJSONFixture(t, gitRef{Ref: "refs/tags/" + refName, Object: gitObject{Type: "tag", SHA: tagSHA}})
		fixture.responses[prefix+"/git/tags/"+tagSHA] = mustJSONFixture(t, gitTag{Tag: refName, SHA: tagSHA, Object: gitObject{Type: "commit", SHA: commitSHA}})
		refType, refSHA, chain = "tag", tagSHA, []expectedTagObject{{SHA1: tagSHA, Name: refName, TargetType: "commit", TargetSHA1: commitSHA}}
	}

	contractFiles := make([]contractFile, 0, len(files))
	var logical int64
	for _, file := range files {
		size := int64(len(file.content))
		contractFiles = append(contractFiles, contractFile{
			SourceKey: file.sourceKey, Path: file.path, Mode: file.mode, GitBlobSHA1: gitBlobSHA1(file.content),
			RawSHA256: sha256Of(file.content), Bytes: size, ExpectedPathResolution: pathResolutionFor(file.path, file.mode, file.content),
		})
		logical += size
	}
	targetCore := contractTargetCore{
		AuthorityID: "retrieval-source-authority:" + refName, SourceSetID: "source-acquisition-set:" + refName,
		ComponentID: "cmp", ComponentVersion: refName, Repository: repository,
		Publisher:         publisher{PublisherID: "publisher:github:acme", Name: "Acme", URI: "https://github.com/acme"},
		LicenseExpression: "Apache-2.0", RequestedTag: refName, RefKind: refKind,
		ExpectedRefType: refType, ExpectedRefSHA1: refSHA, ExpectedTagObjects: chain,
		ExpectedCommitSHA1: commitSHA, ExpectedRootTreeSHA1: rootSHA, Files: contractFiles,
	}
	targetCoreBytes, err := canonicalJSON(targetCore)
	if err != nil {
		t.Fatalf("canonical target core: %v", err)
	}
	targetDigest := sha256.Sum256(targetCoreBytes)
	target := contractTarget{TargetID: "source-acquisition-target:sha256:" + hex.EncodeToString(targetDigest[:]), contractTargetCore: targetCore}
	core := contractCore{
		Schema: contractSchema, SchemaVersion: contractSchemaVersion, Canonicalization: canonicalProfile, ContractKind: contractKind,
		WorkID: "TEST-RUNNER-" + refType, AuthorityState: "non_authoritative", ReviewState: "implementation_frozen",
		CompileEligible: false, PromoteEligible: false, AuthorityBoundary: authorityBoundary{},
		SourceDenominator:     sourceDenominator{FreezeID: "retrieval-evaluation-freeze:test", FreezeDocumentSHA256: sha256Of([]byte("freeze")), ComparisonOnly: true},
		AcquisitionCapability: reviewedCapabilities["github-git-objects-rest-exact-file-v2"], ExecutionGate: gate,
		Bounds: contractBounds{
			Targets: 1, Files: len(files), LogicalBytes: logical, AnnotatedTagDepth: maxAnnotatedTagDepth, PathDepth: maxPathDepth,
			TreeEntries: maxTreeEntries, BlobBytes: maxBlobBytes, HTTPRequests: maxHTTPRequests, HTTPResponseBytes: maxResponseBytes, ObjectJSONBytes: maxObjectJSONBytes,
		},
		Targets: []contractTarget{target},
	}
	return fixture, core
}

func runAcquisition(t *testing.T, fixture *apiFixture, core contractCore) *runResult {
	t.Helper()
	contract, _, err := materializeContract(core)
	if err != nil {
		t.Fatalf("materialize contract: %v", err)
	}
	server := httptest.NewServer(fixture)
	defer server.Close()
	githubRunner, err := newRunner(server.Client(), server.URL, "", true, contract)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	store, err := newCASStore(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatalf("new CAS store: %v", err)
	}
	defer store.close()
	result, err := githubRunner.run(context.Background(), contract, store)
	if err != nil {
		t.Fatalf("run acquisition: %v", err)
	}
	return result
}

func runAcquisitionErr(t *testing.T, fixture *apiFixture, core contractCore) error {
	t.Helper()
	contract, _, err := materializeContract(core)
	if err != nil {
		t.Fatalf("materialize contract: %v", err)
	}
	server := httptest.NewServer(fixture)
	defer server.Close()
	githubRunner, err := newRunner(server.Client(), server.URL, "", true, contract)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	store, err := newCASStore(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatalf("new CAS store: %v", err)
	}
	defer store.close()
	_, err = githubRunner.run(context.Background(), contract, store)
	return err
}

func TestRunnerAcquiresTagTarget(t *testing.T) {
	fixture, core := buildRunnerContract(t, "acme/widgets", "", "v1.2.3", runnerSampleFiles())
	result := runAcquisition(t, fixture, core)
	if !strings.HasPrefix(result.Receipt.ReceiptID, "source-acquisition-receipt:sha256:") {
		t.Fatalf("unexpected receipt id: %q", result.Receipt.ReceiptID)
	}
	if len(result.Receipt.Targets) != 1 {
		t.Fatalf("unexpected target count: %d", len(result.Receipt.Targets))
	}
	resolution := result.Receipt.Targets[0].TagResolution
	if resolution.Ref != "refs/tags/v1.2.3" || resolution.InitialObjectType != "tag" || len(resolution.AnnotatedTagObjects) != 1 {
		t.Fatalf("tag resolution drifted: %+v", resolution)
	}
	if result.Proposal.ProposalID == "" || result.Receipt.Counts.Files != 3 {
		t.Fatalf("tag acquisition receipt/proposal incomplete: %+v", result.Receipt.Counts)
	}
}

func TestRunnerAcquiresBranchTarget(t *testing.T) {
	fixture, core := buildRunnerContract(t, "acme/untagged", "branch", "main", runnerSampleFiles())
	result := runAcquisition(t, fixture, core)
	if len(result.Receipt.Targets) != 1 {
		t.Fatalf("unexpected target count: %d", len(result.Receipt.Targets))
	}
	resolution := result.Receipt.Targets[0].TagResolution
	if resolution.Ref != "refs/heads/main" || resolution.InitialObjectType != "commit" || len(resolution.AnnotatedTagObjects) != 0 {
		t.Fatalf("branch resolution drifted: %+v", resolution)
	}
	if resolution.ResolvedCommitSHA1 != result.Receipt.Targets[0].ExpectedCommitSHA1 {
		t.Fatalf("branch did not resolve to the pinned commit: %+v", resolution)
	}
	if result.Proposal.ProposalID == "" || result.Receipt.Counts.Files != 3 {
		t.Fatalf("branch acquisition receipt/proposal incomplete: %+v", result.Receipt.Counts)
	}
}

func TestRunnerBranchSpoofedHeadFailsClosed(t *testing.T) {
	fixture, core := buildRunnerContract(t, "acme/untagged", "branch", "main", runnerSampleFiles())
	// Serve a heads ref that resolves to a different commit than the contract pins.
	spoof := labelSHA1("commit:spoofed-head")
	fixture.responses["/repos/acme/untagged/git/ref/heads/main"] = mustJSONFixture(t, gitRef{Ref: "refs/heads/main", Object: gitObject{Type: "commit", SHA: spoof}})
	err := runAcquisitionErr(t, fixture, core)
	if err == nil || !strings.Contains(err.Error(), "branch ref drifted from the exact object binding") {
		t.Fatalf("expected spoofed-head rejection, got %v", err)
	}
}

func TestRunnerBranchRedirectFailsClosed(t *testing.T) {
	fixture, core := buildRunnerContract(t, "acme/untagged", "branch", "main", runnerSampleFiles())
	fixture.redirectEndpoint = "/repos/acme/untagged/git/ref/heads/main"
	err := runAcquisitionErr(t, fixture, core)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}
