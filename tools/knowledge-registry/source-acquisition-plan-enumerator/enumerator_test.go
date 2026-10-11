package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// --- Synthetic GitHub Git-object fixture ---------------------------------
//
// Blob SHA-1s are the REAL Git 'blob <n>\0<raw>' hashes of the fixture content
// so the enumerator's reconstruction proof exercises real bytes. Tree, commit,
// and tag object SHA-1s are synthetic-but-canonical 40-hex labels: the
// enumerator only checks that a Git-object response echoes the SHA it asked for
// (getTree/getCommit), never that a tree SHA equals a recomputed tree hash, so
// synthetic tree identities are faithful to what the data plane verifies.

type apiFixture struct {
	responses           map[string][]byte
	redirectEndpoint    string
	requireExactHeaders bool
}

func gitBlobSHA1(content []byte) string {
	digest := sha1.Sum(append([]byte("blob "+strconv.Itoa(len(content))+"\x00"), content...))
	return hex.EncodeToString(digest[:])
}

func labelSHA1(label string) string {
	digest := sha1.Sum([]byte(label))
	return hex.EncodeToString(digest[:])
}

type treeNode struct {
	children map[string]*treeNode // dir name -> subtree
	blobs    map[string][]byte    // file name -> content
	modes    map[string]string    // file name -> mode
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

// emit assigns a synthetic tree SHA to this node, registers its tree response
// and every descendant's tree/blob response, and returns this node's SHA.
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
		fixture.responses[prefix+"/git/blobs/"+blobSHA] = mustJSON(t, gitBlob{SHA: blobSHA, Size: &size, Encoding: "base64", Content: base64.StdEncoding.EncodeToString(content)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	truncated := false
	fixture.responses[prefix+"/git/trees/"+treeSHA] = mustJSON(t, gitTree{SHA: treeSHA, Tree: entries, Truncated: &truncated})
	return treeSHA
}

type fixtureFile struct {
	sourceKey string
	path      string
	mode      string
	content   []byte
}

// buildAnnotatedFixture builds an annotated-tag target and returns the fixture
// plus the resolved commit SHA and per-file blob SHA-1s.
func buildAnnotatedFixture(t *testing.T, repository, tag string, files []fixtureFile) (*apiFixture, string, map[string]string) {
	t.Helper()
	fixture := &apiFixture{responses: map[string][]byte{}, requireExactHeaders: true}
	prefix := "/repos/" + repository
	root := newTreeNode()
	for _, file := range files {
		root.insert(strings.Split(file.path, "/"), file.mode, file.content)
	}
	rootSHA := root.emit(prefix, "", fixture, t)
	commitSHA := labelSHA1("commit:" + repository + ":" + tag)
	commit := gitCommit{SHA: commitSHA}
	commit.Tree.SHA = rootSHA
	fixture.responses[prefix+"/git/commits/"+commitSHA] = mustJSON(t, commit)
	tagSHA := labelSHA1("tag:" + repository + ":" + tag)
	fixture.responses[prefix+"/git/ref/tags/"+tag] = mustJSON(t, gitRef{Ref: "refs/tags/" + tag, Object: gitObject{Type: "tag", SHA: tagSHA}})
	fixture.responses[prefix+"/git/tags/"+tagSHA] = mustJSON(t, gitTag{Tag: tag, SHA: tagSHA, Object: gitObject{Type: "commit", SHA: commitSHA}})
	blobSHAs := map[string]string{}
	for _, file := range files {
		blobSHAs[file.sourceKey] = gitBlobSHA1(file.content)
	}
	return fixture, commitSHA, blobSHAs
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

func fixtureEnumerator(t *testing.T, fixture *apiFixture, request planRequest) (*enumerator, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(fixture)
	value, err := newEnumerator(server.Client(), server.URL, "", true, request)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return value, server
}

func sampleFiles() []fixtureFile {
	return []fixtureFile{
		{sourceKey: "guide", path: "docs/network/guide.md", mode: "100644", content: []byte("# Guide\n\nExact bytes for the guide.\n")},
		{sourceKey: "lib", path: "src/lib.go", mode: "100644", content: []byte("package lib\n\nfunc Answer() int { return 42 }\n")},
		{sourceKey: "tool", path: "src/cmd/tool.sh", mode: "100755", content: []byte("#!/bin/sh\necho tool\n")},
	}
}

func sampleRequest(repository, tag, commit string) planRequest {
	return planRequest{
		WorkID:                         "source-acquisition-plan-enumerator:test",
		FreezeID:                       fixtureFreezeID,
		FreezeDocumentSHA256:           fixtureFreezeDocumentSHA256,
		ExecutionManifestID:            fixtureExecutionManifestID,
		ExecutionManifestPayloadSHA256: fixtureExecutionManifestSHA,
		Targets: []targetRequest{{
			AuthorityID: "retrieval-source-authority:acme:v1.2.3", SourceSetID: "source-acquisition-set:acme:v1.2.3",
			ComponentID: "acme", ComponentVersion: "v1.2.3", Repository: repository,
			Publisher:         publisher{PublisherID: "publisher:github:acme", Name: "Acme", URI: "https://github.com/acme"},
			LicenseExpression: "Apache-2.0", RequestedTag: tag, ExpectedCommitSHA1: commit,
			Files: []fileSelection{{SourceKey: "guide", Path: "docs/network/guide.md"}, {SourceKey: "lib", Path: "src/lib.go"}, {SourceKey: "tool", Path: "src/cmd/tool.sh"}},
		}},
	}
}

func TestEnumeratesDeterministicPlan(t *testing.T) {
	repository, tag := "acme/widgets", "v1.2.3"
	fixture, commit, blobSHAs := buildAnnotatedFixture(t, repository, tag, sampleFiles())
	request := sampleRequest(repository, tag, commit)

	firstEnum, firstServer := fixtureEnumerator(t, fixture, request)
	first, firstDoc, err := firstEnum.enumerate(context.Background(), request)
	firstServer.Close()
	if err != nil {
		t.Fatalf("first enumeration: %v", err)
	}
	secondEnum, secondServer := fixtureEnumerator(t, fixture, request)
	defer secondServer.Close()
	second, secondDoc, err := secondEnum.enumerate(context.Background(), request)
	if err != nil {
		t.Fatalf("second enumeration: %v", err)
	}
	if !bytes.Equal(firstDoc, secondDoc) || first.ContractID != second.ContractID {
		t.Fatal("independent enumerations were not byte-identical")
	}
	if !bytes.HasSuffix(firstDoc, []byte{'\n'}) || !strings.HasPrefix(first.ContractID, contractIDPrefix) || !validSHA256(first.ContractPayloadSHA256) {
		t.Fatal("contract identity or serialization is malformed")
	}
	if first.AuthorityState != contractAuthorityState || first.ReviewState != contractReviewState || first.CompileEligible || first.PromoteEligible || first.AuthorityBoundary != (authorityBoundary{}) {
		t.Fatal("contract authority boundary widened")
	}
	if first.Bounds.Targets != 1 || first.Bounds.Files != 3 {
		t.Fatalf("unexpected bounds: %+v", first.Bounds)
	}
	var wantBytes int64
	for _, file := range sampleFiles() {
		wantBytes += int64(len(file.content))
	}
	if first.Bounds.LogicalBytes != wantBytes {
		t.Fatalf("logical bytes = %d, want %d", first.Bounds.LogicalBytes, wantBytes)
	}
	target := first.Targets[0]
	if target.ExpectedRefType != "tag" || target.ExpectedCommitSHA1 != commit || len(target.ExpectedTagObjects) != 1 || target.ExpectedTagObjects[0].TargetSHA1 != commit {
		t.Fatalf("tag resolution not recorded: %+v", target.ExpectedTagObjects)
	}
	byKey := map[string]contractFile{}
	for _, file := range target.Files {
		byKey[file.SourceKey] = file
	}
	if byKey["guide"].GitBlobSHA1 != blobSHAs["guide"] || byKey["tool"].Mode != "100755" {
		t.Fatalf("recorded blob identity or mode drifted: %+v", byKey)
	}
	// Every file's tree chain must reconnect through validation.
	if err := validatePlan(first.planCore); err != nil {
		t.Fatalf("authored plan failed its own validation: %v", err)
	}
	// The deepest path binds three intermediate trees plus the terminal blob.
	if got := len(byKey["guide"].ExpectedPathResolution); got != 3 {
		t.Fatalf("guide path resolution length = %d, want 3", got)
	}
}

func TestTamperedBlobFailsClosed(t *testing.T) {
	repository, tag := "acme/widgets", "v1.2.3"
	fixture, commit, blobSHAs := buildAnnotatedFixture(t, repository, tag, sampleFiles())
	request := sampleRequest(repository, tag, commit)
	// Overwrite the guide blob response with content of the SAME length but
	// different bytes: it passes the size check yet cannot reproduce the SHA-1
	// the tree edge declares. This is the true tamper case.
	prefix := "/repos/" + repository
	original := []byte("# Guide\n\nExact bytes for the guide.\n")
	tampered := make([]byte, len(original))
	copy(tampered, original)
	tampered[0] = 'X'
	declaredSHA := blobSHAs["guide"]
	if gitBlobSHA1(tampered) == declaredSHA {
		t.Fatal("tampered content unexpectedly reproduced the declared SHA-1")
	}
	size := int64(len(tampered))
	fixture.responses[prefix+"/git/blobs/"+declaredSHA] = mustJSON(t, gitBlob{SHA: declaredSHA, Size: &size, Encoding: "base64", Content: base64.StdEncoding.EncodeToString(tampered)})

	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	_, _, err := enum.enumerate(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "does not reproduce the declared Git SHA-1") {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}

func TestWrongExpectedCommitFailsClosed(t *testing.T) {
	repository, tag := "acme/widgets", "v1.2.3"
	fixture, _, _ := buildAnnotatedFixture(t, repository, tag, sampleFiles())
	request := sampleRequest(repository, tag, labelSHA1("commit:not-the-real-commit"))
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	_, _, err := enum.enumerate(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "terminate at the pinned commit") {
		t.Fatalf("expected pinned-commit rejection, got %v", err)
	}
}

func TestMissingPathFailsClosed(t *testing.T) {
	repository, tag := "acme/widgets", "v1.2.3"
	fixture, commit, _ := buildAnnotatedFixture(t, repository, tag, sampleFiles())
	request := sampleRequest(repository, tag, commit)
	request.Targets[0].Files = append(request.Targets[0].Files, fileSelection{SourceKey: "ghost", Path: "docs/missing.md"})
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	_, _, err := enum.enumerate(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "no exact requested child") {
		t.Fatalf("expected missing-path rejection, got %v", err)
	}
}

func TestRedirectFailsClosed(t *testing.T) {
	repository, tag := "acme/widgets", "v1.2.3"
	fixture, commit, _ := buildAnnotatedFixture(t, repository, tag, sampleFiles())
	fixture.redirectEndpoint = "/repos/" + repository + "/git/ref/tags/" + tag
	request := sampleRequest(repository, tag, commit)
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	_, _, err := enum.enumerate(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

func TestLightweightTagBindsCommitDirectly(t *testing.T) {
	repository, tag := "acme/lite", "v0.1.0"
	fixture := &apiFixture{responses: map[string][]byte{}, requireExactHeaders: true}
	prefix := "/repos/" + repository
	root := newTreeNode()
	content := []byte("lightweight\n")
	root.insert([]string{"README.md"}, "100644", content)
	rootSHA := root.emit(prefix, "", fixture, t)
	commitSHA := labelSHA1("commit:lite")
	commit := gitCommit{SHA: commitSHA}
	commit.Tree.SHA = rootSHA
	fixture.responses[prefix+"/git/commits/"+commitSHA] = mustJSON(t, commit)
	// Lightweight tag: the ref points directly at the commit, no tag object.
	fixture.responses[prefix+"/git/ref/tags/"+tag] = mustJSON(t, gitRef{Ref: "refs/tags/" + tag, Object: gitObject{Type: "commit", SHA: commitSHA}})
	request := planRequest{
		WorkID:                         "lite",
		FreezeID:                       fixtureFreezeID,
		FreezeDocumentSHA256:           fixtureFreezeDocumentSHA256,
		ExecutionManifestID:            fixtureExecutionManifestID,
		ExecutionManifestPayloadSHA256: fixtureExecutionManifestSHA,
		Targets: []targetRequest{{
			AuthorityID: "a", SourceSetID: "s", ComponentID: "c", ComponentVersion: "v0.1.0", Repository: repository,
			Publisher: publisher{PublisherID: "p", Name: "n", URI: "u"}, LicenseExpression: "MIT",
			RequestedTag: tag, ExpectedCommitSHA1: commitSHA, Files: []fileSelection{{SourceKey: "readme", Path: "README.md"}},
		}},
	}
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	plan, _, err := enum.enumerate(context.Background(), request)
	if err != nil {
		t.Fatalf("lightweight enumeration: %v", err)
	}
	target := plan.Targets[0]
	if target.ExpectedRefType != "commit" || len(target.ExpectedTagObjects) != 0 || target.ExpectedRefSHA1 != commitSHA {
		t.Fatalf("lightweight ref binding drifted: %+v", target)
	}
	if err := validatePlan(plan.planCore); err != nil {
		t.Fatalf("lightweight plan failed validation: %v", err)
	}
}

// buildBranchFixture builds a branch-HEAD target: the heads ref points directly
// at the commit, with no tag object. It returns the fixture, the resolved commit
// SHA, and per-file blob SHA-1s.
func buildBranchFixture(t *testing.T, repository, branch string, files []fixtureFile) (*apiFixture, string, map[string]string) {
	t.Helper()
	fixture := &apiFixture{responses: map[string][]byte{}, requireExactHeaders: true}
	prefix := "/repos/" + repository
	root := newTreeNode()
	for _, file := range files {
		root.insert(strings.Split(file.path, "/"), file.mode, file.content)
	}
	rootSHA := root.emit(prefix, "", fixture, t)
	commitSHA := labelSHA1("commit:" + repository + ":" + branch)
	commit := gitCommit{SHA: commitSHA}
	commit.Tree.SHA = rootSHA
	fixture.responses[prefix+"/git/commits/"+commitSHA] = mustJSON(t, commit)
	fixture.responses[prefix+"/git/ref/heads/"+branch] = mustJSON(t, gitRef{Ref: "refs/heads/" + branch, Object: gitObject{Type: "commit", SHA: commitSHA}})
	blobSHAs := map[string]string{}
	for _, file := range files {
		blobSHAs[file.sourceKey] = gitBlobSHA1(file.content)
	}
	return fixture, commitSHA, blobSHAs
}

func sampleBranchRequest(repository, branch, commit string) planRequest {
	request := sampleRequest(repository, branch, commit)
	request.Targets[0].RefKind = "branch"
	return request
}

func TestBranchRefBindsCommitDirectly(t *testing.T) {
	repository, branch := "acme/untagged", "main"
	fixture, commit, blobSHAs := buildBranchFixture(t, repository, branch, sampleFiles())
	request := sampleBranchRequest(repository, branch, commit)
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	plan, document, err := enum.enumerate(context.Background(), request)
	if err != nil {
		t.Fatalf("branch enumeration: %v", err)
	}
	target := plan.Targets[0]
	if target.RefKind != "branch" || target.RequestedTag != branch {
		t.Fatalf("branch ref kind or name not carried: %+v", target)
	}
	if target.ExpectedRefType != "commit" || target.ExpectedRefSHA1 != commit || len(target.ExpectedTagObjects) != 0 {
		t.Fatalf("branch must bind the commit directly with an empty chain: %+v", target)
	}
	if !bytes.Contains(document, []byte("\"ref_kind\":\"branch\"")) {
		t.Fatal("emitted branch contract does not carry ref_kind")
	}
	byKey := map[string]contractFile{}
	for _, file := range target.Files {
		byKey[file.SourceKey] = file
	}
	if byKey["guide"].GitBlobSHA1 != blobSHAs["guide"] || byKey["tool"].Mode != "100755" {
		t.Fatalf("recorded blob identity or mode drifted: %+v", byKey)
	}
	if err := validatePlan(plan.planCore); err != nil {
		t.Fatalf("authored branch plan failed its own validation: %v", err)
	}
}

func TestBranchWrongExpectedCommitFailsClosed(t *testing.T) {
	repository, branch := "acme/untagged", "main"
	fixture, _, _ := buildBranchFixture(t, repository, branch, sampleFiles())
	request := sampleBranchRequest(repository, branch, labelSHA1("commit:not-the-branch-head"))
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	_, _, err := enum.enumerate(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "branch head does not resolve to the pinned commit") {
		t.Fatalf("expected branch head mismatch rejection, got %v", err)
	}
}

func TestBranchRedirectFailsClosed(t *testing.T) {
	repository, branch := "acme/untagged", "main"
	fixture, commit, _ := buildBranchFixture(t, repository, branch, sampleFiles())
	fixture.redirectEndpoint = "/repos/" + repository + "/git/ref/heads/" + branch
	request := sampleBranchRequest(repository, branch, commit)
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	_, _, err := enum.enumerate(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

func TestBadBranchNameFailsClosed(t *testing.T) {
	request := sampleBranchRequest("acme/untagged", "main", labelSHA1("commit:branch"))
	// A ".." in a branch name must fail closed at request validation, before any
	// network call — the branch pattern admits '/', so this guards the extra bans.
	request.Targets[0].RequestedTag = "release/../escape"
	if _, err := newEnumerator(http.DefaultClient, apiOrigin, "", false, request); err == nil {
		t.Fatal("expected a traversal branch name to be rejected before any network call")
	}
}

func TestInvalidRefKindFailsClosed(t *testing.T) {
	request := sampleRequest("acme/widgets", "v1.2.3", labelSHA1("commit:widgets"))
	request.Targets[0].RefKind = "sha"
	if _, err := newEnumerator(http.DefaultClient, apiOrigin, "", false, request); err == nil {
		t.Fatal("expected an unknown ref kind to be rejected before any network call")
	}
}

func TestTagContractOmitsRefKind(t *testing.T) {
	repository, tag := "acme/widgets", "v1.2.3"
	fixture, commit, _ := buildAnnotatedFixture(t, repository, tag, sampleFiles())
	request := sampleRequest(repository, tag, commit)
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	_, document, err := enum.enumerate(context.Background(), request)
	if err != nil {
		t.Fatalf("tag enumeration: %v", err)
	}
	if bytes.Contains(document, []byte("ref_kind")) {
		t.Fatal("tag contract must omit ref_kind to stay byte-identical to historical contracts")
	}
}

func TestPlanRequestRejectsAliasing(t *testing.T) {
	repository, tag := "acme/widgets", "v1.2.3"
	_, commit, _ := buildAnnotatedFixture(t, repository, tag, sampleFiles())
	request := sampleRequest(repository, tag, commit)
	request.Targets = append(request.Targets, request.Targets[0])
	if err := validatePlanRequest(request); err == nil || !strings.Contains(err.Error(), "aliases source authorities") {
		t.Fatalf("expected authority-alias rejection, got %v", err)
	}
}

func TestOfflineWithoutNetworkOnValidationFailure(t *testing.T) {
	// A malformed request must fail before any HTTP request is issued.
	request := planRequest{WorkID: "", Targets: nil}
	if _, err := newEnumerator(http.DefaultClient, apiOrigin, "", false, request); err == nil {
		t.Fatal("expected constructor to reject an empty plan request")
	}
}
