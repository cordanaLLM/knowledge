package main

import (
	"bytes"
	"context"
	"crypto/sha1"
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type fixtureResponse struct {
	status  int
	body    []byte
	headers map[string]string
}

type gitHubFixture struct {
	t         *testing.T
	mu        sync.Mutex
	responses map[string]fixtureResponse
	requests  []string
}

func TestRunnerCompleteTraversalCASAndByteIdenticalReplay(t *testing.T) {
	selected := fixtureAcceptedPlan(t)
	fixture := newGitHubFixture(t)
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	firstRunner := fixtureRunner(t, server)
	first, err := firstRunner.run(context.Background(), selected, store)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first.Receipt.AuthorityState != "non_authoritative" || first.Receipt.ReviewState != "unreviewed" || first.Receipt.CompileEligible || first.Receipt.PromoteEligible {
		t.Fatal("receipt widened authority")
	}
	if first.Proposal.AuthorityState != "non_authoritative" || first.Proposal.ReviewState != "unreviewed" || first.Proposal.CompileEligible || first.Proposal.PromoteEligible {
		t.Fatal("proposal widened authority")
	}
	if first.Receipt.Counts.Targets != 2 || first.Receipt.Counts.Files != 4 || first.Receipt.Counts.LogicalBytes != int64(len("rollouts-chart")+len("rollouts-template")+len("workflows-chart")) {
		t.Fatalf("unexpected receipt counts: %#v", first.Receipt.Counts)
	}
	if len(first.Receipt.Targets[0].TagResolution.AnnotatedTagObjects) != 0 || len(first.Receipt.Targets[1].TagResolution.AnnotatedTagObjects) != 1 {
		t.Fatal("lightweight/annotated tag evidence was not retained")
	}
	for _, target := range first.Receipt.Targets {
		if len(target.SubtreeResolution) != 3 || target.SubtreeResolution[0].Path != "" || target.SubtreeResolution[2].Path != target.ContentRoot {
			t.Fatalf("incomplete subtree chain: %#v", target.SubtreeResolution)
		}
		for _, file := range target.Files {
			raw, err := os.ReadFile(filepath.Join(store.root, filepath.FromSlash(file.CASPath)))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			if file.RawSHA256 != "sha256:"+hex.EncodeToString(digest[:]) || int64(len(raw)) != file.Bytes {
				t.Fatalf("CAS content mismatch for %s", file.Path)
			}
		}
	}
	assertPublishedBytes(t, store, first.ReceiptPath, first.ReceiptBytes)
	assertPublishedBytes(t, store, first.ProposalPath, first.ProposalBytes)
	if bytes.Contains(first.ReceiptBytes, []byte("fixture-secret")) || bytes.Contains(first.ProposalBytes, []byte("fixture-secret")) {
		t.Fatal("credential leaked into durable output")
	}
	secondRunner := fixtureRunner(t, server)
	second, err := secondRunner.run(context.Background(), selected, store)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !bytes.Equal(first.ReceiptBytes, second.ReceiptBytes) || !bytes.Equal(first.ProposalBytes, second.ProposalBytes) || first.Receipt.ReceiptID != second.Receipt.ReceiptID || first.Proposal.ProposalID != second.Proposal.ProposalID {
		t.Fatal("identical Git objects did not produce byte-identical replay")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	for _, request := range fixture.requests {
		if strings.Contains(request, "?") || strings.Contains(request, "recursive") {
			t.Fatalf("runner used a recursive or query-based tree request: %s", request)
		}
	}
}

func TestRunnerCrashLeavesNoReceiptAndRecoversFromCAS(t *testing.T) {
	selected := fixtureAcceptedPlan(t)
	fixture := newGitHubFixture(t)
	failedPath := fixtureBlobPath(blobSHA([]byte("workflows-chart")))
	original := fixture.responses[failedPath]
	fixture.responses[failedPath] = fixtureResponse{status: http.StatusInternalServerError, body: []byte(`{"message":"fixture failure"}`)}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixtureRunner(t, server).run(context.Background(), selected, store); err == nil {
		t.Fatal("partial response unexpectedly produced a complete run")
	}
	assertDirectoryEmpty(t, filepath.Join(store.root, "receipts"))
	assertDirectoryEmpty(t, filepath.Join(store.root, "inventory-proposals"))
	fixture.mu.Lock()
	fixture.responses[failedPath] = original
	fixture.mu.Unlock()
	if _, err := fixtureRunner(t, server).run(context.Background(), selected, store); err != nil {
		t.Fatalf("recovery run: %v", err)
	}
}

func TestRunnerReceiptOnlyCrashRecoversProposalWithoutMutableRefReplay(t *testing.T) {
	selected := fixtureAcceptedPlan(t)
	fixture := newGitHubFixture(t)
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	first, err := fixtureRunner(t, server).run(context.Background(), selected, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.root, filepath.FromSlash(first.ProposalPath))); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	requestsBeforeRecovery := len(fixture.requests)
	refPath := fixtureRefPath(expectedTargets[0].RequestedTag)
	fixture.responses[refPath] = fixtureJSON(gitRef{Ref: "refs/tags/" + expectedTargets[0].RequestedTag, Object: gitObject{Type: "commit", SHA: objectSHA("force-moved-after-receipt")}})
	fixture.mu.Unlock()
	recovered, err := fixtureRunner(t, server).run(context.Background(), selected, store)
	if err != nil {
		t.Fatalf("receipt-only recovery: %v", err)
	}
	if !bytes.Equal(first.ReceiptBytes, recovered.ReceiptBytes) || !bytes.Equal(first.ProposalBytes, recovered.ProposalBytes) || first.Proposal.ProposalID != recovered.Proposal.ProposalID {
		t.Fatal("receipt-only recovery changed deterministic output")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.requests) != requestsBeforeRecovery {
		t.Fatal("receipt-only recovery recontacted the mutable GitHub ref")
	}
}

func TestRunnerRejectsTruncatedTreeAndPagination(t *testing.T) {
	selected := fixtureAcceptedPlan(t)
	for _, test := range []struct {
		name   string
		mutate func(*gitHubFixture)
		want   string
	}{
		{
			name: "truncated tree",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				var tree map[string]any
				mustUnmarshal(t, fixture.responses[path].body, &tree)
				tree["truncated"] = true
				fixture.responses[path] = fixtureJSON(tree)
			},
			want: "truncated",
		},
		{
			name: "pagination signal",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				response := fixture.responses[path]
				response.headers = map[string]string{"Link": `<https://api.github.test/next>; rel="next"`}
				fixture.responses[path] = response
			},
			want: "pagination",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitHubFixture(t)
			test.mutate(fixture)
			server := httptest.NewServer(fixture)
			defer server.Close()
			store, err := newTestStore(t)
			if err != nil {
				t.Fatal(err)
			}
			_, err = fixtureRunner(t, server).run(context.Background(), selected, store)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wanted %q failure, got %v", test.want, err)
			}
			assertDirectoryEmpty(t, filepath.Join(store.root, "receipts"))
			assertDirectoryEmpty(t, filepath.Join(store.root, "inventory-proposals"))
		})
	}
}

func TestRunnerRejectsAdversarialGitObjects(t *testing.T) {
	selected := fixtureAcceptedPlan(t)
	for _, test := range []struct {
		name   string
		mutate func(*gitHubFixture)
		want   string
	}{
		{
			name: "blob sha mismatch",
			mutate: func(fixture *gitHubFixture) {
				sha := blobSHA([]byte("rollouts-chart"))
				fixture.responses[fixtureBlobPath(sha)] = fixtureJSON(gitBlob{SHA: sha, Size: int64Pointer(int64(len("rollouts-chart"))), Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("tampered-chart"))})
			},
			want: "Git SHA-1",
		},
		{
			name: "symlink mode",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				var tree gitTree
				mustUnmarshal(t, fixture.responses[path].body, &tree)
				tree.Tree[0].Mode = "120000"
				fixture.responses[path] = fixtureJSON(tree)
			},
			want: "unsupported Git tree entry",
		},
		{
			name: "path traversal",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				var tree gitTree
				mustUnmarshal(t, fixture.responses[path].body, &tree)
				tree.Tree[0].Path = "../Chart.yaml"
				fixture.responses[path] = fixtureJSON(tree)
			},
			want: "noncanonical Git tree name",
		},
		{
			name: "duplicate path",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				var tree gitTree
				mustUnmarshal(t, fixture.responses[path].body, &tree)
				tree.Tree = append(tree.Tree, tree.Tree[0])
				fixture.responses[path] = fixtureJSON(tree)
			},
			want: "duplicate path",
		},
		{
			name: "empty subtree",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				fixture.responses[path] = fixtureJSON(treeFixture(objectSHA("rollouts-subtree"), []gitTreeEntry{}))
			},
			want: "contains no files",
		},
		{
			name: "wrong tag commit",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureRefPath(expectedTargets[0].RequestedTag)
				fixture.responses[path] = fixtureJSON(gitRef{Ref: "refs/tags/" + expectedTargets[0].RequestedTag, Object: gitObject{Type: "commit", SHA: objectSHA("wrong-commit")}})
			},
			want: "accepted commit",
		},
		{
			name: "duplicate response key",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureCommitPath(expectedTargets[0].ExpectedCommit)
				fixture.responses[path] = fixtureResponse{status: http.StatusOK, body: []byte(fmt.Sprintf(`{"sha":%q,"sha":%q,"tree":{"sha":%q}}`, expectedTargets[0].ExpectedCommit, expectedTargets[0].ExpectedCommit, objectSHA("rollouts-root")))}
			},
			want: "duplicate key",
		},
		{
			name: "annotated tag cycle",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTagPath(objectSHA("workflows-annotated-tag"))
				var tag gitTag
				mustUnmarshal(t, fixture.responses[path].body, &tag)
				tag.Object = gitObject{Type: "tag", SHA: tag.SHA}
				fixture.responses[path] = fixtureJSON(tag)
			},
			want: "cycle",
		},
		{
			name: "over-bound annotated tag name",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTagPath(objectSHA("workflows-annotated-tag"))
				var tag gitTag
				mustUnmarshal(t, fixture.responses[path].body, &tag)
				tag.Tag = strings.Repeat("a", maxTagObjectNameRunes+1)
				fixture.responses[path] = fixtureJSON(tag)
			},
			want: "annotated tag name",
		},
		{
			name: "tree identity swap",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				var tree gitTree
				mustUnmarshal(t, fixture.responses[path].body, &tree)
				tree.SHA = objectSHA("swapped-tree")
				fixture.responses[path] = fixtureJSON(tree)
			},
			want: "tree response is swapped",
		},
		{
			name: "tree cycle",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				var tree gitTree
				mustUnmarshal(t, fixture.responses[path].body, &tree)
				tree.Tree[1].SHA = objectSHA("rollouts-root")
				fixture.responses[path] = fixtureJSON(tree)
			},
			want: "tree cycle",
		},
		{
			name: "content root cycle",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-root"))
				var tree gitTree
				mustUnmarshal(t, fixture.responses[path].body, &tree)
				tree.Tree[0].SHA = tree.SHA
				fixture.responses[path] = fixtureJSON(tree)
			},
			want: "content-root tree cycle",
		},
		{
			name: "over-bound inventory path",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				var tree gitTree
				mustUnmarshal(t, fixture.responses[path].body, &tree)
				tree.Tree[0].Path = strings.Repeat("a", maxInventoryPathBytes+1)
				fixture.responses[path] = fixtureJSON(tree)
			},
			want: "inventory path",
		},
		{
			name: "tree entry bound",
			mutate: func(fixture *gitHubFixture) {
				path := fixtureTreePath(objectSHA("rollouts-subtree"))
				entries := make([]gitTreeEntry, maxTreeEntries+1)
				fixture.responses[path] = fixtureJSON(treeFixture(objectSHA("rollouts-subtree"), entries))
			},
			want: "entry bound",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitHubFixture(t)
			test.mutate(fixture)
			server := httptest.NewServer(fixture)
			defer server.Close()
			store, err := newTestStore(t)
			if err != nil {
				t.Fatal(err)
			}
			_, err = fixtureRunner(t, server).run(context.Background(), selected, store)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wanted %q failure, got %v", test.want, err)
			}
			assertDirectoryEmpty(t, filepath.Join(store.root, "receipts"))
			assertDirectoryEmpty(t, filepath.Join(store.root, "inventory-proposals"))
		})
	}
}

func TestPlanValidationRejectsDuplicateKeysReaddressingAndAuthorityWidening(t *testing.T) {
	selected, raw, allowedID := fixturePlanMaterial(t)
	if selected.PlanID != allowedID {
		t.Fatal("fixture plan did not validate")
	}
	duplicate := bytes.Replace(raw, []byte(`"schema_version":"3.0.0"`), []byte(`"schema_version":"3.0.0","schema_version":"3.0.0"`), 1)
	if _, err := parsePlan(duplicate, allowedID); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate-key plan was not rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "execution authority",
			mutate: func(value map[string]any) {
				value["execution_boundary"].(map[string]any)["network_access"] = true
			},
			want: "execution boundary widened",
		},
		{
			name: "target broadening",
			mutate: func(value map[string]any) {
				value["targets"].([]any)[0].(map[string]any)["expected_commit"] = objectSHA("other")
			},
			want: "immutable target identity",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated, mutatedID := readdressPlan(t, raw, test.mutate)
			if _, err := parsePlan(mutated, mutatedID); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wanted %q failure, got %v", test.want, err)
			}
		})
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
	if info, err := os.Lstat(final); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("rejected CAS symlink was altered or removed: %v, %v", info, err)
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
	existing, err := os.ReadFile(conflictingFinal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(existing, incomplete) {
		t.Fatal("conflicting final path was altered or deleted")
	}
}

func TestCASFullBytesBeforeFsyncFailureAreDurablyRehabilitated(t *testing.T) {
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
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
	final := filepath.Join(store.root, "cas", "sha256", hexDigest[:2], hexDigest)
	if got, err := os.ReadFile(final); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("full uncertain bytes were not retained: %q, %v", got, err)
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
		t.Fatalf("retry did not fsync both exact file and directory: files=%d dirs=%d", regularSyncs, directorySyncs)
	}
}

func TestCASParentReplacementFailsClosedAndRetainsWriterInode(t *testing.T) {
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
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
		t.Fatalf("writer-owned bytes were not retained in the anchored directory: %q, %v", got, err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("replacement directory unexpectedly received output: %v, %v", entries, err)
	}
}

func TestCASRejectsWritableExistingExactObject(t *testing.T) {
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	raw := []byte("writable-object")
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
	if err := os.Chmod(final, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := store.putBlob(rawSHA, raw); err == nil || !strings.Contains(err.Error(), "accessible by group or world") {
		t.Fatalf("writable exact object was accepted: %v", err)
	}
	if got, err := os.ReadFile(final); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("rejected writable object was altered: %q, %v", got, err)
	}
}

func TestCASRejectsReadableOrHardlinkedExistingExactObject(t *testing.T) {
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
			t.Cleanup(func() { _ = store.close() })
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
}

func TestCASRejectsNonPrivateOutputRoot(t *testing.T) {
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
	t.Cleanup(func() { _ = store.close() })
	receiptID := "source-acquisition-receipt:sha256:" + strings.Repeat("a", 64)
	proposalID := "source-inventory-proposal:sha256:" + strings.Repeat("b", 64)
	if _, err := store.putReceipt(receiptID, []byte("receipt\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.putProposal(proposalID, []byte("proposal\n")); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublishedRunSet(store, receiptID, []byte("receipt\n"), proposalID, []byte("proposal\n")); err != nil {
		t.Fatalf("exact singleton set was rejected: %v", err)
	}
	extra := filepath.Join(store.root, "receipts", strings.Repeat("c", 64)+".json")
	if err := os.WriteFile(extra, []byte("ambiguous\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublishedRunSet(store, receiptID, []byte("receipt\n"), proposalID, []byte("proposal\n")); err == nil || !strings.Contains(err.Error(), "entry bound") {
		t.Fatalf("ambiguous receipt set was accepted: %v", err)
	}
}

func TestRunnerRejectsAmbiguousFinalPublicationSet(t *testing.T) {
	selected := fixtureAcceptedPlan(t)
	fixture := newGitHubFixture(t)
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	store, err := newTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	if err := os.WriteFile(filepath.Join(store.root, "inventory-proposals", strings.Repeat("a", 64)+".json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixtureRunner(t, server).run(context.Background(), selected, store); err == nil || !strings.Contains(err.Error(), "without its predecessor receipt") {
		t.Fatalf("orphan proposal did not fail closed: %v", err)
	}
}

func TestHTTPRedirectAndAmbiguousResponseHeadersFailClosed(t *testing.T) {
	if _, err := newRunner(http.DefaultClient, "https://api.github.com", "do-not-print\nheader", false); err == nil || strings.Contains(err.Error(), "do-not-print") {
		t.Fatalf("invalid token was accepted or disclosed: %v", err)
	}
	var redirected atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		redirected.Store(true)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{}`))
	}))
	t.Cleanup(destination.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+"/credential-target", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	redirectRunner, err := newRunner(redirector.Client(), redirector.URL, "fixture-secret", true)
	if err != nil {
		t.Fatal(err)
	}
	var commit gitCommit
	err = redirectRunner.getJSON(context.Background(), "argoproj/argo-helm", "/git/commits/"+expectedTargets[0].ExpectedCommit, &commit)
	if err == nil || !strings.Contains(err.Error(), "redirects are forbidden") || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("redirect did not fail closed without token disclosure: %v", err)
	}
	if redirected.Load() {
		t.Fatal("redirect destination was contacted")
	}

	for _, test := range []struct {
		name    string
		headers func(http.Header)
		want    string
	}{
		{
			name: "duplicate content type",
			headers: func(header http.Header) {
				header.Add("Content-Type", "application/json")
				header.Add("Content-Type", "application/json")
			},
			want: "ambiguous or missing content type",
		},
		{
			name: "multiple content encodings",
			headers: func(header http.Header) {
				header.Set("Content-Type", "application/json")
				header.Add("Content-Encoding", "identity")
				header.Add("Content-Encoding", "gzip")
			},
			want: "unexpected content encoding",
		},
		{
			name: "empty pagination header",
			headers: func(header http.Header) {
				header.Set("Content-Type", "application/json")
				header.Add("Link", "")
			},
			want: "pagination Link header",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				test.headers(writer.Header())
				_, _ = writer.Write([]byte(`{}`))
			}))
			defer server.Close()
			value, err := newRunner(server.Client(), server.URL, "", true)
			if err != nil {
				t.Fatal(err)
			}
			err = value.getJSON(context.Background(), "argoproj/argo-helm", "/git/commits/"+expectedTargets[0].ExpectedCommit, &commit)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wanted %q failure, got %v", test.want, err)
			}
		})
	}
}

func TestRunnerContractDigestIsFrozen(t *testing.T) {
	actual, err := runnerContractDigest()
	if err != nil {
		t.Fatal(err)
	}
	if actual != runnerContractSHA256 {
		t.Fatalf("runner contract digest changed: %s", actual)
	}
}

func TestEmitSchemaValidationFixtures(t *testing.T) {
	planPath := os.Getenv("P1_SRC02_TEST_PLAN")
	outputRoot := os.Getenv("P1_SRC02_TEST_OUTPUT_ROOT")
	if planPath == "" && outputRoot == "" {
		t.Skip("set P1_SRC02_TEST_PLAN and P1_SRC02_TEST_OUTPUT_ROOT for the schema integration fixture")
	}
	if planPath == "" || outputRoot == "" {
		t.Fatal("both P1_SRC02_TEST_PLAN and P1_SRC02_TEST_OUTPUT_ROOT are required")
	}
	selected, err := loadPlan(planPath, acceptedPlanID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newGitHubFixture(t)
	server := httptest.NewServer(fixture)
	defer server.Close()
	store, err := newCASStore(outputRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixtureRunner(t, server).run(context.Background(), selected, store); err != nil {
		t.Fatal(err)
	}
}

func (fixture *gitHubFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if request.Method != http.MethodGet || request.URL.RawQuery != "" {
		http.Error(writer, "unexpected method or query", http.StatusBadRequest)
		return
	}
	if request.Header.Get("Accept") != "application/vnd.github+json" || request.Header.Get("X-GitHub-Api-Version") != apiVersion || request.Header.Get("Authorization") != "Bearer fixture-secret" || request.Header.Get("Accept-Encoding") != "identity" || request.Header.Get("User-Agent") != "archeion-source-acquisition-runner/"+runnerVersion {
		http.Error(writer, "missing pinned headers", http.StatusBadRequest)
		return
	}
	fixture.requests = append(fixture.requests, request.URL.RequestURI())
	response, ok := fixture.responses[request.URL.Path]
	if !ok {
		http.Error(writer, "fixture object absent", http.StatusNotFound)
		return
	}
	for key, value := range response.headers {
		writer.Header().Set(key, value)
	}
	writer.Header().Set("Content-Type", "application/json")
	status := response.status
	if status == 0 {
		status = http.StatusOK
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(response.body)
}

func newGitHubFixture(t *testing.T) *gitHubFixture {
	t.Helper()
	fixture := &gitHubFixture{t: t, responses: make(map[string]fixtureResponse)}
	rolloutsRoot := objectSHA("rollouts-root")
	rolloutsCharts := objectSHA("rollouts-charts")
	rolloutsSubtree := objectSHA("rollouts-subtree")
	rolloutsTemplates := objectSHA("rollouts-templates")
	workflowsRoot := objectSHA("workflows-root")
	workflowsCharts := objectSHA("workflows-charts")
	workflowsSubtree := objectSHA("workflows-subtree")
	rolloutsChart := []byte("rollouts-chart")
	rolloutsTemplate := []byte("rollouts-template")
	workflowsChart := []byte("workflows-chart")
	empty := []byte{}
	rolloutsChartSHA := blobSHA(rolloutsChart)
	rolloutsTemplateSHA := blobSHA(rolloutsTemplate)
	workflowsChartSHA := blobSHA(workflowsChart)
	emptySHA := blobSHA(empty)
	fixture.responses[fixtureRefPath(expectedTargets[0].RequestedTag)] = fixtureJSON(gitRef{Ref: "refs/tags/" + expectedTargets[0].RequestedTag, Object: gitObject{Type: "commit", SHA: expectedTargets[0].ExpectedCommit}})
	annotatedSHA := objectSHA("workflows-annotated-tag")
	fixture.responses[fixtureRefPath(expectedTargets[1].RequestedTag)] = fixtureJSON(gitRef{Ref: "refs/tags/" + expectedTargets[1].RequestedTag, Object: gitObject{Type: "tag", SHA: annotatedSHA}})
	fixture.responses[fixtureTagPath(annotatedSHA)] = fixtureJSON(gitTag{Tag: expectedTargets[1].RequestedTag, SHA: annotatedSHA, Object: gitObject{Type: "commit", SHA: expectedTargets[1].ExpectedCommit}})
	fixture.responses[fixtureCommitPath(expectedTargets[0].ExpectedCommit)] = fixtureJSON(commitFixture(expectedTargets[0].ExpectedCommit, rolloutsRoot))
	fixture.responses[fixtureCommitPath(expectedTargets[1].ExpectedCommit)] = fixtureJSON(commitFixture(expectedTargets[1].ExpectedCommit, workflowsRoot))
	fixture.responses[fixtureTreePath(rolloutsRoot)] = fixtureJSON(treeFixture(rolloutsRoot, []gitTreeEntry{{Path: "charts", Mode: "040000", Type: "tree", SHA: rolloutsCharts}, {Path: "outside", Mode: "160000", Type: "commit", SHA: objectSHA("ignored-gitlink")}}))
	fixture.responses[fixtureTreePath(rolloutsCharts)] = fixtureJSON(treeFixture(rolloutsCharts, []gitTreeEntry{{Path: "argo-rollouts", Mode: "040000", Type: "tree", SHA: rolloutsSubtree}}))
	fixture.responses[fixtureTreePath(rolloutsSubtree)] = fixtureJSON(treeFixture(rolloutsSubtree, []gitTreeEntry{{Path: "Chart.yaml", Mode: "100644", Type: "blob", SHA: rolloutsChartSHA, Size: int64Pointer(int64(len(rolloutsChart)))}, {Path: "templates", Mode: "040000", Type: "tree", SHA: rolloutsTemplates}}))
	fixture.responses[fixtureTreePath(rolloutsTemplates)] = fixtureJSON(treeFixture(rolloutsTemplates, []gitTreeEntry{{Path: "deploy.yaml", Mode: "100755", Type: "blob", SHA: rolloutsTemplateSHA, Size: int64Pointer(int64(len(rolloutsTemplate)))}}))
	fixture.responses[fixtureTreePath(workflowsRoot)] = fixtureJSON(treeFixture(workflowsRoot, []gitTreeEntry{{Path: "charts", Mode: "040000", Type: "tree", SHA: workflowsCharts}}))
	fixture.responses[fixtureTreePath(workflowsCharts)] = fixtureJSON(treeFixture(workflowsCharts, []gitTreeEntry{{Path: "argo-workflows", Mode: "040000", Type: "tree", SHA: workflowsSubtree}}))
	fixture.responses[fixtureTreePath(workflowsSubtree)] = fixtureJSON(treeFixture(workflowsSubtree, []gitTreeEntry{{Path: "Chart.yaml", Mode: "100644", Type: "blob", SHA: workflowsChartSHA, Size: int64Pointer(int64(len(workflowsChart)))}, {Path: "empty.txt", Mode: "100644", Type: "blob", SHA: emptySHA, Size: int64Pointer(0)}}))
	for sha, raw := range map[string][]byte{rolloutsChartSHA: rolloutsChart, rolloutsTemplateSHA: rolloutsTemplate, workflowsChartSHA: workflowsChart, emptySHA: empty} {
		fixture.responses[fixtureBlobPath(sha)] = fixtureJSON(gitBlob{SHA: sha, Size: int64Pointer(int64(len(raw))), Encoding: "base64", Content: base64.StdEncoding.EncodeToString(raw)})
	}
	return fixture
}

func fixtureRunner(t *testing.T, server *httptest.Server) *runner {
	t.Helper()
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return errors.New("redirect rejected") }
	value, err := newRunner(client, server.URL, "fixture-secret", true)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func fixtureAcceptedPlan(t *testing.T) *plan {
	t.Helper()
	selected, _, _ := fixturePlanMaterial(t)
	return selected
}

func fixturePlanMaterial(t *testing.T) (*plan, []byte, string) {
	t.Helper()
	value := plan{
		Schema:                "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-plan.schema.json",
		SchemaVersion:         "3.0.0",
		RecordSchemaVersion:   "1.0.0",
		PlanKind:              "reviewed_source_acquisition_plan",
		AuthorityState:        "non_authoritative",
		ReviewState:           "not_applicable",
		AuthorityBoundary:     map[string]bool{"source_admission": false, "retrieval_release": false, "signing": false, "pointer_mutation": false, "git_mutation": false, "production_mutation": false},
		ExecutionBoundary:     map[string]bool{"execution_authorized": false, "network_access": false, "cache_mutation": false, "inventory_emission": false},
		AcquisitionCapability: capability{CapabilityID: "github-git-objects-rest-v1", CapabilityContractSHA256: capabilityDigest, Transport: "https-json", APIOrigin: apiOrigin, APIVersion: apiVersion, ObjectFormat: "sha1", SupportedModes: []string{"040000", "100644", "100755"}},
	}
	value.Generator.Name = "archeion-reviewed-source-acquisition"
	value.Generator.Version = "5"
	value.Generator.Source = "tools/knowledge-registry/acquire_sources.py"
	value.ArtifactBundle.BundleID = acceptedBundleID
	value.ArtifactBundle.PayloadSHA256 = strings.TrimPrefix(acceptedBundleID, "accepted-record-artifact-bundle:")
	value.ArtifactBundle.SuccessorRecordSetID = "reviewed-record-set:sha256:a2a00248b70e028385f9ff9d20109a0d221952350ce5cc919913acde46a75ad2"
	value.ArtifactBundle.AcceptanceOutcomeID = "source-acceptance-outcome:sha256:9d46784ca9183d120045525b156171b9de7f4c473688ecfccba19055bb33b475"
	value.Selection.Mode = "explicit_exact"
	value.Selection.ComponentIDs = []string{expectedTargets[0].ComponentID, expectedTargets[1].ComponentID}
	value.Counts.Total = 2
	value.Counts.Ready = 2
	for _, expected := range expectedTargets {
		target := planTarget{TargetID: expected.TargetID, State: "ready", RecordLogicalPath: expected.RecordLogicalPath, ArtifactBundleID: acceptedBundleID, RecordSHA256: expected.RecordSHA256, RecordID: expected.RecordID, ComponentID: expected.ComponentID, ComponentVersionID: expected.ComponentVersionID, ComponentKind: "chart", Lifecycle: "deployed", Repository: "argoproj/argo-helm", ResolvedVersion: expected.ResolvedVersion, RequestedTag: expected.RequestedTag, ExpectedCommit: expected.ExpectedCommit, ContentRoots: []string{expected.ContentRoot}, SourceResolutionReviewState: "accepted", AcquisitionCapability: "github-git-objects-rest-v1", ChannelType: "source", Gaps: []json.RawMessage{}}
		target.RecordArtifact.Base = "bundle"
		target.RecordArtifact.Path = expected.RecordArtifactPath
		target.RecordArtifact.ContentSHA256 = expected.RecordSHA256
		target.RecordArtifact.Bytes = expected.RecordArtifactBytes
		target.TargetIdentity.Repository = target.Repository
		target.TargetIdentity.RequestedTag = target.RequestedTag
		target.TargetIdentity.ExpectedCommit = target.ExpectedCommit
		target.TargetIdentity.ContentRoots = target.ContentRoots
		value.Targets = append(value.Targets, target)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	mustUnmarshal(t, raw, &generic)
	delete(generic, "plan_id")
	delete(generic, "plan_payload_sha256")
	payload, err := canonicalJSON(generic)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	value.PlanPayloadSHA256 = "sha256:" + hex.EncodeToString(digest[:])
	value.PlanID = "source-acquisition-plan:" + value.PlanPayloadSHA256
	raw, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := parsePlan(raw, value.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	return selected, raw, value.PlanID
}

func readdressPlan(t *testing.T, raw []byte, mutate func(map[string]any)) ([]byte, string) {
	t.Helper()
	var value map[string]any
	mustUnmarshal(t, raw, &value)
	mutate(value)
	delete(value, "plan_id")
	delete(value, "plan_payload_sha256")
	payload, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	value["plan_payload_sha256"] = payloadSHA
	value["plan_id"] = "source-acquisition-plan:" + payloadSHA
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result, value["plan_id"].(string)
}

func fixtureJSON(value any) fixtureResponse {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return fixtureResponse{status: http.StatusOK, body: raw}
}

func treeFixture(sha string, entries []gitTreeEntry) gitTree {
	truncated := false
	return gitTree{SHA: sha, Tree: entries, Truncated: &truncated}
}

func commitFixture(sha, treeSHA string) gitCommit {
	value := gitCommit{SHA: sha}
	value.Tree.SHA = treeSHA
	return value
}

func objectSHA(label string) string {
	digest := sha1.Sum([]byte(label))
	return hex.EncodeToString(digest[:])
}

func blobSHA(raw []byte) string {
	digest := sha1.Sum(append([]byte(fmt.Sprintf("blob %d\x00", len(raw))), raw...))
	return hex.EncodeToString(digest[:])
}

func fixtureRefPath(tag string) string    { return "/repos/argoproj/argo-helm/git/ref/tags/" + tag }
func fixtureTagPath(sha string) string    { return "/repos/argoproj/argo-helm/git/tags/" + sha }
func fixtureCommitPath(sha string) string { return "/repos/argoproj/argo-helm/git/commits/" + sha }
func fixtureTreePath(sha string) string   { return "/repos/argoproj/argo-helm/git/trees/" + sha }
func fixtureBlobPath(sha string) string   { return "/repos/argoproj/argo-helm/git/blobs/" + sha }

func int64Pointer(value int64) *int64 { return &value }

func mustUnmarshal(t *testing.T, raw []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(raw, destination); err != nil {
		t.Fatal(err)
	}
}

func assertPublishedBytes(t *testing.T, store *casStore, relative string, expected []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(store.root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("published bytes differ at %s", relative)
	}
}

func assertDirectoryEmpty(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no completed output in %s, found %d entries", path, len(entries))
	}
}

func newTestStore(t *testing.T) (*casStore, error) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	return newCASStore(root)
}
