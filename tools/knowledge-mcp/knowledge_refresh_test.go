package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func committedKnowledgeGeneration(t *testing.T, parent, name, content string) (string, string) {
	t.Helper()
	root := filepath.Join(parent, name)
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"init", "-q", root},
		{"-C", root, "config", "user.name", "Knowledge MCP test"},
		{"-C", root, "config", "user.email", "knowledge-mcp-test@example.invalid"},
	} {
		if output, err := exec.Command(gitExecutablePath, arguments...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "generation.md"), []byte(content+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"-C", root, "add", "docs/generation.md"},
		{"-C", root, "commit", "-qm", name},
	} {
		if output, err := exec.Command(gitExecutablePath, arguments...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}
	output, err := exec.Command(gitExecutablePath, "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return root, strings.TrimSpace(string(output))
}

func rotateGenerationLink(t *testing.T, link, target string) {
	t.Helper()
	temporary := link + ".next"
	if err := os.Remove(temporary); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(target, temporary); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, link); err != nil {
		t.Fatal(err)
	}
}

func searchKnowledgeForTest(t *testing.T, service *toolService, query string) toolOutcome {
	t.Helper()
	arguments, err := json.Marshal(map[string]any{"query": query, "limit": 4})
	if err != nil {
		t.Fatal(err)
	}
	return service.call(context.Background(), "knowledge_search", arguments)
}

func TestKnowledgeRefreshAtomicallyFollowsRotatedGeneration(t *testing.T) {
	parent := t.TempDir()
	firstRoot, firstRevision := committedKnowledgeGeneration(t, parent, "first", "alpha generation evidence")
	secondRoot, secondRevision := committedKnowledgeGeneration(t, parent, "second", "bravo generation evidence")
	link := filepath.Join(parent, "current")
	rotateGenerationLink(t, link, firstRoot)

	service := newToolService(buildKnowledgeIndex(link), newRegistryProvider(config{maxRegistrySize: defaultMaxRegistryBytes}))
	if result := searchKnowledgeForTest(t, service, "alpha"); result.Error || result.State != stateOK {
		t.Fatalf("initial generation was not searchable: %#v", result)
	}
	descriptor := service.knowledgeDescriptor()
	if descriptor["indexed_commit"] != firstRevision || descriptor["resolved_root"] != firstRoot {
		t.Fatalf("initial generation identity missing: %#v", descriptor)
	}

	rotateGenerationLink(t, link, secondRoot)
	changed, err := service.refreshKnowledge(link)
	if err != nil || !changed {
		t.Fatalf("rotated generation did not refresh: changed=%v err=%v", changed, err)
	}
	fresh := searchKnowledgeForTest(t, service, "bravo")
	if fresh.Error || fresh.State != stateOK {
		t.Fatalf("new generation was not searchable: %#v", fresh)
	}
	generation := fresh.Data["repository_generation"].(map[string]any)
	if generation["indexed_commit"] != secondRevision || generation["source_current"] != true {
		t.Fatalf("search result omitted its serving generation: %#v", fresh)
	}
	if result := searchKnowledgeForTest(t, service, "alpha"); result.State != stateEmpty || result.Error {
		t.Fatalf("retired generation remained visible: %#v", result)
	}
	descriptor = service.knowledgeDescriptor()
	refresh, ok := descriptor["refresh"].(map[string]any)
	if !ok || refresh["source_current"] != true || descriptor["indexed_commit"] != secondRevision ||
		descriptor["resolved_root"] != secondRoot || descriptor["indexed_at"] == nil {
		t.Fatalf("refreshed generation identity/freshness missing: %#v", descriptor)
	}
	if changed, err = service.refreshKnowledge(link); err != nil || changed {
		t.Fatalf("unchanged generation rebuilt: changed=%v err=%v", changed, err)
	}
}

func TestKnowledgeRefreshFailureKeepsLastCompleteGeneration(t *testing.T) {
	parent := t.TempDir()
	goodRoot, _ := committedKnowledgeGeneration(t, parent, "good", "retained stable evidence")
	link := filepath.Join(parent, "current")
	rotateGenerationLink(t, link, goodRoot)
	service := newToolService(buildKnowledgeIndex(link), newRegistryProvider(config{maxRegistrySize: defaultMaxRegistryBytes}))

	brokenRoot := filepath.Join(parent, "broken")
	if err := os.Mkdir(brokenRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	rotateGenerationLink(t, link, brokenRoot)
	if changed, err := service.refreshKnowledge(link); err == nil || changed {
		t.Fatalf("broken candidate replaced the serving generation: changed=%v err=%v", changed, err)
	}
	if result := searchKnowledgeForTest(t, service, "retained stable evidence"); result.Error || result.State != stateStale || result.Data["result_state"] != stateOK {
		t.Fatalf("last complete generation was not retained: %#v", result)
	}
	refresh := service.knowledgeDescriptor()["refresh"].(map[string]any)
	if service.knowledgeDescriptor()["state"] != stateStale {
		t.Fatalf("failed refresh did not mark repository status stale: %#v", service.knowledgeDescriptor())
	}
	if refresh["source_current"] != false || refresh["last_error"] == nil || refresh["last_error_at"] == nil {
		t.Fatalf("refresh failure was not exposed: %#v", refresh)
	}

	rotateGenerationLink(t, link, goodRoot)
	if changed, err := service.refreshKnowledge(link); err != nil || changed {
		t.Fatalf("return to the serving generation should be a clean no-op: changed=%v err=%v", changed, err)
	}
	refresh = service.knowledgeDescriptor()["refresh"].(map[string]any)
	if refresh["source_current"] != true || refresh["last_error"] != nil {
		t.Fatalf("successful source check did not clear the transient failure: %#v", refresh)
	}
}

func TestKnowledgeStatusDistinguishesObservedAndIndexedDuringBuild(t *testing.T) {
	parent := t.TempDir()
	firstRoot, firstRevision := committedKnowledgeGeneration(t, parent, "status-first", "status old evidence")
	secondRoot, secondRevision := committedKnowledgeGeneration(t, parent, "status-second", "status new evidence")
	link := filepath.Join(parent, "current")
	rotateGenerationLink(t, link, firstRoot)
	service := newToolService(buildKnowledgeIndex(link), newRegistryProvider(config{maxRegistrySize: defaultMaxRegistryBytes}))

	started := make(chan struct{})
	release := make(chan struct{})
	service.knowledgeMu.Lock()
	service.knowledgeIndexBuilder = func(generation repositoryGeneration, limits knowledgeLimits) *knowledgeIndex {
		close(started)
		<-release
		return buildKnowledgeIndexForGeneration(generation, limits)
	}
	service.knowledgeMu.Unlock()
	rotateGenerationLink(t, link, secondRoot)
	type refreshResult struct {
		changed bool
		err     error
	}
	result := make(chan refreshResult, 1)
	go func() {
		changed, err := service.refreshKnowledge(link)
		result <- refreshResult{changed: changed, err: err}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("candidate index build did not start")
	}

	descriptor := service.knowledgeDescriptor()
	refresh := descriptor["refresh"].(map[string]any)
	if descriptor["state"] != stateStale || descriptor["indexed_state"] != stateOK ||
		descriptor["indexed_commit"] != firstRevision || refresh["observed_commit"] != secondRevision ||
		refresh["observed_resolved_root"] != secondRoot || refresh["source_current"] != false ||
		refresh["build_in_progress"] != true {
		t.Fatalf("status collapsed serving and observed generations: %#v", descriptor)
	}
	if old := searchKnowledgeForTest(t, service, "old"); old.Error || old.State != stateStale || old.Data["result_state"] != stateOK {
		t.Fatalf("serving index was unavailable during candidate build: %#v", old)
	}
	close(release)
	select {
	case completed := <-result:
		if completed.err != nil || !completed.changed {
			t.Fatalf("candidate did not publish: %#v", completed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("candidate index build did not finish")
	}
}

func TestKnowledgeRefreshDiscardsCandidateSupersededDuringBuild(t *testing.T) {
	parent := t.TempDir()
	firstRoot, firstRevision := committedKnowledgeGeneration(t, parent, "supersede-first", "supersede retained evidence")
	secondRoot, _ := committedKnowledgeGeneration(t, parent, "supersede-second", "supersede discarded evidence")
	thirdRoot, thirdRevision := committedKnowledgeGeneration(t, parent, "supersede-third", "supersede newest evidence")
	link := filepath.Join(parent, "current")
	rotateGenerationLink(t, link, firstRoot)
	service := newToolService(buildKnowledgeIndex(link), newRegistryProvider(config{maxRegistrySize: defaultMaxRegistryBytes}))

	started := make(chan struct{})
	release := make(chan struct{})
	service.knowledgeMu.Lock()
	service.knowledgeIndexBuilder = func(generation repositoryGeneration, limits knowledgeLimits) *knowledgeIndex {
		close(started)
		<-release
		return buildKnowledgeIndexForGeneration(generation, limits)
	}
	service.knowledgeMu.Unlock()
	rotateGenerationLink(t, link, secondRoot)
	result := make(chan error, 1)
	go func() {
		changed, err := service.refreshKnowledge(link)
		if changed && err == nil {
			err = fmt.Errorf("superseded candidate was published")
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("superseded candidate build did not start")
	}
	rotateGenerationLink(t, link, thirdRoot)
	close(release)
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "changed while") {
			t.Fatalf("superseded candidate did not fail closed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("superseded candidate build did not finish")
	}

	descriptor := service.knowledgeDescriptor()
	refresh := descriptor["refresh"].(map[string]any)
	if descriptor["state"] != stateStale || descriptor["indexed_commit"] != firstRevision ||
		refresh["observed_commit"] != thirdRevision || refresh["observed_resolved_root"] != thirdRoot ||
		refresh["source_current"] != false || refresh["build_in_progress"] != false || refresh["last_error"] == nil {
		t.Fatalf("superseded generation status is incomplete: %#v", descriptor)
	}
}

func TestKnowledgeWatcherRefreshesWithoutRestart(t *testing.T) {
	parent := t.TempDir()
	firstRoot, _ := committedKnowledgeGeneration(t, parent, "watch-first", "watcher old evidence")
	secondRoot, secondRevision := committedKnowledgeGeneration(t, parent, "watch-second", "watcher fresh evidence")
	link := filepath.Join(parent, "current")
	rotateGenerationLink(t, link, firstRoot)
	service := newToolService(buildKnowledgeIndex(link), newRegistryProvider(config{maxRegistrySize: defaultMaxRegistryBytes}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.watchKnowledge(ctx, link, 10*time.Millisecond, nil)
	rotateGenerationLink(t, link, secondRoot)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if service.knowledgeDescriptor()["indexed_commit"] == secondRevision {
			if result := searchKnowledgeForTest(t, service, "fresh"); !result.Error && result.State == stateOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("watcher did not publish revision %s: %#v", secondRevision, service.knowledgeDescriptor())
}

func TestKnowledgeRefreshIntervalBounds(t *testing.T) {
	root := t.TempDir()
	if _, err := loadConfig([]string{"--repository-root", root, "--repository-refresh-interval", "999ms"}, func(string) string { return "" }); err == nil {
		t.Fatal("sub-second repository refresh interval was accepted")
	}
	configuration, err := loadConfig([]string{"--repository-root", root, "--repository-refresh-interval", "1m"}, func(string) string { return "" })
	if err != nil || configuration.repositoryRefreshInterval != time.Minute {
		t.Fatalf("valid repository refresh interval was rejected: value=%s err=%v", configuration.repositoryRefreshInterval, err)
	}
}
