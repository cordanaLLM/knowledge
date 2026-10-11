package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultKnowledgeRefreshInterval = 15 * time.Second

// repositoryGeneration identifies one immutable git-sync worktree. git-sync
// builds the target directory first and atomically rotates its configured link,
// so resolving the link before indexing gives the broker a stable build input.
type repositoryGeneration struct {
	configuredRoot string
	resolvedRoot   string
	revision       string
}

func inspectRepositoryGeneration(root string) (repositoryGeneration, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return repositoryGeneration{}, fmt.Errorf("resolve repository root: %w", err)
	}
	absolute = filepath.Clean(absolute)
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return repositoryGeneration{}, fmt.Errorf("resolve repository generation: %w", err)
	}
	resolved = filepath.Clean(resolved)
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return repositoryGeneration{}, fmt.Errorf("resolved repository generation is not a readable directory: %s", resolved)
	}
	return repositoryGeneration{
		configuredRoot: absolute,
		resolvedRoot:   resolved,
		revision:       readRepositoryRevision(resolved),
	}, nil
}

// A repository without a commit can still have useful staged files in tests
// and local development. The resolved git-sync target remains the generation
// identity in that case; production checkouts additionally expose exact HEAD.
func readRepositoryRevision(root string) string {
	output, overflow, err := runGitCommand(root, maxGitRootOutputBytes, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || overflow {
		return ""
	}
	revision := stringTrimSpace(string(output))
	if len(revision) != 40 && len(revision) != 64 {
		return ""
	}
	for _, value := range revision {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return ""
		}
	}
	return revision
}

func sameRepositoryGeneration(left, right repositoryGeneration) bool {
	return left.resolvedRoot == right.resolvedRoot && left.revision == right.revision
}

func indexRepositoryGeneration(index *knowledgeIndex) repositoryGeneration {
	if index == nil {
		return repositoryGeneration{}
	}
	return repositoryGeneration{
		configuredRoot: index.root,
		resolvedRoot:   index.resolvedRoot,
		revision:       index.indexedRevision,
	}
}

// refreshKnowledge builds beside the serving generation, validates that the
// git-sync link did not rotate again during the build, then swaps only after
// every reader of the old generation has left. The refresh mutex bounds memory
// to one serving index plus one candidate; the RW lock prevents half-built or
// retired generations from being observed by a tool call.
func (service *toolService) refreshKnowledge(root string) (bool, error) {
	service.knowledgeRefreshMu.Lock()
	defer service.knowledgeRefreshMu.Unlock()

	checkedAt := time.Now().UTC()
	generation, err := inspectRepositoryGeneration(root)
	if err != nil {
		service.recordKnowledgeRefreshFailure(checkedAt, err)
		return false, err
	}

	service.knowledgeMu.RLock()
	current := service.knowledge
	unchanged := current != nil && current.state != stateBackendUnavailable &&
		sameRepositoryGeneration(indexRepositoryGeneration(current), generation)
	service.knowledgeMu.RUnlock()
	if unchanged {
		service.recordKnowledgeRefreshCheck(checkedAt, generation)
		return false, nil
	}

	service.knowledgeMu.Lock()
	service.knowledgeLastCheckAt = checkedAt
	service.knowledgeLastErrorAt = time.Time{}
	service.knowledgeLastError = ""
	service.knowledgeSourceCurrent = false
	service.knowledgeObservedRoot = generation.resolvedRoot
	service.knowledgeObservedCommit = generation.revision
	service.knowledgeRefreshBuilding = true
	builder := service.knowledgeIndexBuilder
	service.knowledgeMu.Unlock()
	if builder == nil {
		builder = buildKnowledgeIndexForGeneration
	}
	candidate := builder(generation, productionKnowledgeLimits())
	if candidate == nil {
		err = errors.New("repository index builder returned no candidate")
		service.recordKnowledgeRefreshFailure(checkedAt, err)
		return false, err
	}
	if candidate.state == stateBackendUnavailable {
		message := candidate.message
		if message == "" {
			message = "repository index candidate is unavailable"
		}
		err = errors.New(message)
		service.recordKnowledgeRefreshFailure(checkedAt, err)
		return false, err
	}

	currentGeneration, err := inspectRepositoryGeneration(root)
	if err != nil {
		service.recordKnowledgeRefreshFailure(checkedAt, err)
		return false, err
	}
	if !sameRepositoryGeneration(generation, currentGeneration) {
		service.recordKnowledgeObservation(checkedAt, currentGeneration)
		err = errors.New("repository generation changed while its candidate index was building")
		service.recordKnowledgeRefreshFailure(checkedAt, err)
		return false, err
	}

	service.knowledgeMu.Lock()
	service.knowledge = candidate
	service.knowledgeLastCheckAt = checkedAt
	service.knowledgeLastSuccessAt = candidate.indexedAt
	service.knowledgeLastErrorAt = time.Time{}
	service.knowledgeLastError = ""
	service.knowledgeSourceCurrent = true
	service.knowledgeObservedRoot = candidate.resolvedRoot
	service.knowledgeObservedCommit = candidate.indexedRevision
	service.knowledgeRefreshBuilding = false
	service.knowledgeMu.Unlock()
	return true, nil
}

func (service *toolService) recordKnowledgeRefreshCheck(checkedAt time.Time, generation repositoryGeneration) {
	service.knowledgeMu.Lock()
	service.knowledgeLastCheckAt = checkedAt
	service.knowledgeLastErrorAt = time.Time{}
	service.knowledgeLastError = ""
	service.knowledgeSourceCurrent = true
	service.knowledgeObservedRoot = generation.resolvedRoot
	service.knowledgeObservedCommit = generation.revision
	service.knowledgeRefreshBuilding = false
	service.knowledgeMu.Unlock()
}

func (service *toolService) recordKnowledgeObservation(checkedAt time.Time, generation repositoryGeneration) {
	service.knowledgeMu.Lock()
	service.knowledgeLastCheckAt = checkedAt
	service.knowledgeObservedRoot = generation.resolvedRoot
	service.knowledgeObservedCommit = generation.revision
	service.knowledgeSourceCurrent = false
	service.knowledgeRefreshBuilding = false
	service.knowledgeMu.Unlock()
}

func (service *toolService) recordKnowledgeRefreshFailure(checkedAt time.Time, err error) {
	service.knowledgeMu.Lock()
	service.knowledgeLastCheckAt = checkedAt
	service.knowledgeLastErrorAt = checkedAt
	service.knowledgeLastError = boundString(strings.TrimSpace(err.Error()), 4096)
	service.knowledgeSourceCurrent = false
	service.knowledgeRefreshBuilding = false
	service.knowledgeMu.Unlock()
}

func (service *toolService) watchKnowledge(ctx context.Context, root string, interval time.Duration, logger *log.Logger) {
	if interval <= 0 {
		return
	}
	service.knowledgeMu.Lock()
	service.knowledgeRefreshInterval = interval
	service.knowledgeMu.Unlock()
	refresh := func() {
		changed, err := service.refreshKnowledge(root)
		if err != nil {
			if logger != nil {
				logger.Printf("repository index refresh kept the previous generation: %v", err)
			}
			return
		}
		if changed && logger != nil {
			service.knowledgeMu.RLock()
			revision := service.knowledge.indexedRevision
			resolvedRoot := service.knowledge.resolvedRoot
			service.knowledgeMu.RUnlock()
			logger.Printf("repository index refreshed: revision=%s generation=%s", revision, resolvedRoot)
		}
	}
	refresh()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}
