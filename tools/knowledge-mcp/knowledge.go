package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxKnowledgeFileBytes        = 4 << 20
	maxKnowledgeIndexedFiles     = 50_000
	maxKnowledgeSourceBytes      = 256 << 20
	maxKnowledgeIndexedChunks    = 250_000
	maxKnowledgeTokenOccurrences = 20_000_000
	maxKnowledgeUniqueTerms      = 1_000_000
	maxKnowledgeWarningSamples   = 1_000
	maxKnowledgeEnumeratedPaths  = 500_000
	chunkLines                   = 24
	chunkOverlap                 = 4
	maxSnippetBytes              = 12 << 10
)

type knowledgeLimits struct {
	files            int
	sourceBytes      int64
	chunks           int
	tokenOccurrences int
	uniqueTerms      int
	warnings         int
	enumeratedPaths  int
	gitOutputBytes   int
}

func productionKnowledgeLimits() knowledgeLimits {
	return knowledgeLimits{
		files: maxKnowledgeIndexedFiles, sourceBytes: maxKnowledgeSourceBytes,
		chunks: maxKnowledgeIndexedChunks, tokenOccurrences: maxKnowledgeTokenOccurrences,
		uniqueTerms: maxKnowledgeUniqueTerms, warnings: maxKnowledgeWarningSamples,
		enumeratedPaths: maxKnowledgeEnumeratedPaths, gitOutputBytes: maxGitFileOutputBytes,
	}
}

type knowledgeCap struct {
	Resource string `json:"resource"`
	Limit    int64  `json:"limit"`
	Used     int64  `json:"used"`
	Reason   string `json:"reason"`
}

type evidenceSpan struct {
	AuthorityClass        string  `json:"authority_class"`
	ContentBinding        string  `json:"content_binding"`
	ContentRole           string  `json:"content_role"`
	EvidenceID            string  `json:"evidence_id"`
	InstructionsForbidden bool    `json:"instructions_forbidden"`
	Path                  string  `json:"path"`
	ProvenanceClass       string  `json:"provenance_class"`
	StartLine             int     `json:"start_line"`
	EndLine               int     `json:"end_line"`
	SHA256                string  `json:"sha256"`
	Snippet               string  `json:"snippet"`
	Score                 float64 `json:"score,omitempty"`
	Truncated             bool    `json:"truncated"`
}

type knowledgeFile struct {
	authorityClass  string
	path            string
	provenanceClass string
	hash            string
	size            int
	lines           []string
	pathTerms       map[string]int
	pathTermCount   int
}

type knowledgeChunk struct {
	file      *knowledgeFile
	startLine int
	endLine   int
	terms     map[string]int
	termCount int
	weight    float64
}

type knowledgeIndex struct {
	root                     string
	resolvedRoot             string
	indexedRevision          string
	indexedAt                time.Time
	state                    typedState
	message                  string
	files                    map[string]*knowledgeFile
	chunks                   []knowledgeChunk
	df                       map[string]int
	avgTerms                 float64
	warnings                 []string
	warningCount             int
	warningsExact            bool
	trackedCandidates        int
	trackedCandidatesExact   bool
	excludedUnverifiedMirror int
	excludedMirrorExact      bool
	consideredFiles          int
	indexedSourceBytes       int64
	indexedTokenOccurrences  int
	caps                     map[string]knowledgeCap
	limits                   knowledgeLimits
}

var mirrorRoots = []string{
	"docs/argocd",
	"docs/argo-events",
	"docs/argo-rollouts",
	"docs/argo-workflows",
}

func buildKnowledgeIndex(root string) *knowledgeIndex {
	return buildKnowledgeIndexWithLimits(root, productionKnowledgeLimits())
}

func buildKnowledgeIndexWithLimits(root string, limits knowledgeLimits) *knowledgeIndex {
	generation, err := inspectRepositoryGeneration(root)
	if err != nil {
		return unavailableKnowledgeIndex(root, limits, err)
	}
	return buildKnowledgeIndexForGeneration(generation, limits)
}

func unavailableKnowledgeIndex(root string, limits knowledgeLimits, err error) *knowledgeIndex {
	return &knowledgeIndex{
		root: root, state: stateBackendUnavailable, message: err.Error(),
		files: make(map[string]*knowledgeFile), df: make(map[string]int),
		caps: make(map[string]knowledgeCap), limits: limits, warningsExact: true,
	}
}

func buildKnowledgeIndexForGeneration(generation repositoryGeneration, limits knowledgeLimits) *knowledgeIndex {
	index := &knowledgeIndex{
		root: generation.configuredRoot, resolvedRoot: generation.resolvedRoot,
		indexedRevision: generation.revision,
		state:           stateOK, files: make(map[string]*knowledgeFile),
		df: make(map[string]int), caps: make(map[string]knowledgeCap), limits: limits, warningsExact: true,
	}
	defer func() { index.indexedAt = time.Now().UTC() }()
	if err := limits.validate(); err != nil {
		index.state = stateBackendUnavailable
		index.message = err.Error()
		return index
	}
	paths, trackedCandidates, trackedExact, excludedUnverified, excludedExact, enumerationCaps, err := gitKnowledgeFiles(generation.resolvedRoot, limits)
	if err != nil {
		index.state = stateBackendUnavailable
		index.message = err.Error()
		return index
	}
	index.trackedCandidates = trackedCandidates
	index.trackedCandidatesExact = trackedExact
	index.excludedUnverifiedMirror = excludedUnverified
	index.excludedMirrorExact = excludedExact
	for _, cap := range enumerationCaps {
		index.caps[cap.Resource] = cap
	}

	for _, path := range paths {
		if !isHighSignalPath(path) {
			continue
		}
		if index.consideredFiles >= limits.files {
			index.recordCap("files", int64(limits.files), int64(index.consideredFiles), "additional high-signal files omitted")
			break
		}
		index.consideredFiles++
		content, err := readSafeRelative(generation.resolvedRoot, path, maxKnowledgeFileBytes)
		if err != nil {
			index.addWarning(fmt.Sprintf("%s: %v", path, err))
			continue
		}
		if !utf8.Valid(content) || bytesLookBinary(content) {
			index.addWarning(fmt.Sprintf("%s: non-text content skipped", path))
			continue
		}
		if index.indexedSourceBytes+int64(len(content)) > limits.sourceBytes {
			index.recordCap("source_bytes", limits.sourceBytes, index.indexedSourceBytes, "additional high-signal file bytes omitted")
			break
		}
		lines := splitLines(string(content))
		pathTerms := termFrequency(tokenize(strings.ReplaceAll(path, "/", " ")))
		file := &knowledgeFile{
			authorityClass:  "local_worktree_evidence",
			path:            path,
			provenanceClass: "git_tracked_path_worktree_snapshot",
			hash:            hashBytes(content),
			size:            len(content),
			lines:           lines,
			pathTerms:       pathTerms,
		}
		for _, count := range pathTerms {
			file.pathTermCount += count
		}
		chunks, bodyTokens, fileTerms := prepareFileChunks(file)
		if len(index.chunks)+len(chunks) > limits.chunks {
			index.recordCap("chunks", int64(limits.chunks), int64(len(index.chunks)), "additional whole-file chunks omitted")
			break
		}
		fileTokens := bodyTokens + file.pathTermCount
		if index.indexedTokenOccurrences+fileTokens > limits.tokenOccurrences {
			index.recordCap("token_occurrences", int64(limits.tokenOccurrences), int64(index.indexedTokenOccurrences), "additional whole-file tokens omitted")
			break
		}
		newTerms := 0
		for term := range fileTerms {
			if _, exists := index.df[term]; !exists {
				newTerms++
			}
		}
		if len(index.df)+newTerms > limits.uniqueTerms {
			index.recordCap("unique_terms", int64(limits.uniqueTerms), int64(len(index.df)), "additional whole-file vocabulary omitted")
			break
		}
		index.files[path] = file
		index.chunks = append(index.chunks, chunks...)
		index.indexedSourceBytes += int64(len(content))
		index.indexedTokenOccurrences += fileTokens
		for term := range fileTerms {
			if _, exists := index.df[term]; !exists {
				index.df[term] = 0
			}
		}
		for chunkIndex := range chunks {
			seen := make(map[string]struct{}, len(chunks[chunkIndex].terms)+len(file.pathTerms))
			for term := range chunks[chunkIndex].terms {
				seen[term] = struct{}{}
			}
			for term := range file.pathTerms {
				seen[term] = struct{}{}
			}
			for term := range seen {
				index.df[term]++
			}
		}
	}
	if len(index.chunks) > 0 {
		bodyTokens := 0
		for chunkIndex := range index.chunks {
			bodyTokens += index.chunks[chunkIndex].termCount
		}
		index.avgTerms = float64(bodyTokens) / float64(len(index.chunks))
	}
	if index.warningCount > 0 || len(index.caps) > 0 {
		index.state = statePartial
		if len(index.caps) > 0 {
			index.message = "repository index reached one or more deterministic resource caps"
		} else {
			index.message = "one or more tracked knowledge files could not be indexed"
		}
	}
	return index
}

func (limits knowledgeLimits) validate() error {
	if limits.files < 1 || limits.sourceBytes < 1 || limits.chunks < 1 || limits.tokenOccurrences < 1 ||
		limits.uniqueTerms < 1 || limits.warnings < 1 || limits.enumeratedPaths < 1 || limits.gitOutputBytes < 1 {
		return errors.New("knowledge index resource limits must all be positive")
	}
	return nil
}

func (index *knowledgeIndex) addWarning(message string) {
	if index.warningCount == index.limits.warnings {
		index.warningsExact = false
		index.recordCap("warnings", int64(index.limits.warnings), int64(index.warningCount), "additional warning records omitted")
		return
	}
	index.warningCount++
	index.warnings = append(index.warnings, message)
}

func (index *knowledgeIndex) recordCap(resource string, limit, used int64, reason string) {
	if _, exists := index.caps[resource]; !exists {
		index.caps[resource] = knowledgeCap{Resource: resource, Limit: limit, Used: used, Reason: reason}
	}
}

func gitKnowledgeFiles(root string, limits knowledgeLimits) ([]string, int, bool, int, bool, []knowledgeCap, error) {
	// The committed worktree is the trust boundary. A directory name cannot
	// prove that untracked bytes are official, immutable, or version-correct,
	// so enumerate possible mirror files only to report their exclusion. A
	// future snapshot/proposal manifest may admit them after exact hash and
	// provenance verification.
	tracked, trackedOutputCapped, trackedPathCapped, err := gitFileList(root, []string{"ls-files", "--cached", "-z"}, limits)
	if err != nil {
		return nil, 0, false, 0, false, nil, fmt.Errorf("tracked-file enumeration failed: %w", err)
	}
	arguments := []string{"ls-files", "--others", "--exclude-standard", "-z", "--"}
	arguments = append(arguments, mirrorRoots...)
	untracked, untrackedOutputCapped, untrackedPathCapped, err := gitFileList(root, arguments, limits)
	if err != nil {
		return nil, 0, false, 0, false, nil, fmt.Errorf("unverified-mirror enumeration failed: %w", err)
	}
	sort.Strings(tracked)
	caps := make([]knowledgeCap, 0, 4)
	if trackedOutputCapped {
		caps = append(caps, knowledgeCap{Resource: "tracked_git_output_bytes", Limit: int64(limits.gitOutputBytes), Used: int64(limits.gitOutputBytes), Reason: "tracked path enumeration output truncated"})
	}
	if trackedPathCapped {
		caps = append(caps, knowledgeCap{Resource: "tracked_paths", Limit: int64(limits.enumeratedPaths), Used: int64(len(tracked)), Reason: "tracked path enumeration truncated"})
	}
	if untrackedOutputCapped {
		caps = append(caps, knowledgeCap{Resource: "untracked_git_output_bytes", Limit: int64(limits.gitOutputBytes), Used: int64(limits.gitOutputBytes), Reason: "untracked mirror path enumeration output truncated"})
	}
	if untrackedPathCapped {
		caps = append(caps, knowledgeCap{Resource: "untracked_paths", Limit: int64(limits.enumeratedPaths), Used: int64(len(untracked)), Reason: "untracked mirror path enumeration truncated"})
	}
	return tracked, len(tracked), !trackedOutputCapped && !trackedPathCapped,
		len(untracked), !untrackedOutputCapped && !untrackedPathCapped, caps, nil
}

func gitFileList(root string, arguments []string, limits knowledgeLimits) ([]string, bool, bool, error) {
	output, outputCapped, err := runGitCommand(root, limits.gitOutputBytes, arguments...)
	if err != nil {
		return nil, false, false, err
	}
	parts := strings.Split(string(output), "\x00")
	if outputCapped && len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	paths := make([]string, 0, len(parts))
	pathCapped := false
	for _, path := range parts {
		if path != "" {
			if len(paths) == limits.enumeratedPaths {
				pathCapped = true
				break
			}
			paths = append(paths, filepath.ToSlash(path))
		}
	}
	return paths, outputCapped, pathCapped, nil
}

// operationalRoots carry the declarative GitOps/IaC surface and the automation
// source behind it. An agent cannot answer "how is this cluster configured"
// from prose alone, so these roots admit structured config and source too.
var operationalRoots = []string{
	"apps",
	"argocd-apps",
	"cluster",
	"terraform",
	"ansible",
	"packer",
	"engineering",
	"scripts",
	"tools",
	".claude",
	".githooks",
}

// proseRoots carry curated human knowledge and keep their historic reach.
var proseRoots = []string{
	"knowledge",
	"docs",
	".workingdir2/cluster-2",
	".workingdir2/research",
	".workingdir2/bugs",
}

func isHighSignalPath(path string) bool {
	path = filepath.ToSlash(path)
	if path == "" || isExcludedPath(path) {
		return false
	}
	base := filepath.Base(path)
	if base == "AGENTS.md" || base == "README.md" || path == "PRINCIPLES.md" || path == "STATE.md" || path == "CLAUDE.md" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch {
	case isOperationalPath(path):
		return isProseExtension(ext) || isStructuredExtension(ext) || isSourceExtension(ext)
	case isProsePath(path):
		// Structured evidence is admitted only where it is itself the record:
		// pinned upstream mirrors and the signed registry.
		return isProseExtension(ext) ||
			((isMirrorPath(path) || strings.HasPrefix(path, "knowledge/")) && isStructuredExtension(ext))
	}
	return false
}

// isExcludedPath denies bytes that must never enter the index regardless of
// root or extension: ciphertext, real variable and credential material,
// machine content-addressed blobs, lockfiles, fixtures and vendored trees.
func isExcludedPath(path string) bool {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))
	switch {
	// Sealed ciphertext decodes to nothing an agent can reason about.
	case strings.HasPrefix(path, "sealed-secrets/sealed/"),
		strings.HasSuffix(base, ".sealed.yaml"), strings.HasSuffix(base, ".sealed.yml"):
		return true
	// Real Terraform variable files hold live infrastructure values; the
	// committed *.tfvars.example templates stay indexable.
	case ext == ".tfvars":
		return true
	// Ansible vault ciphertext and any credential material.
	case base == "vault.yml", base == "vault.yaml", base == "kubeconfig",
		ext == ".key", ext == ".pem", ext == ".crt", ext == ".p12", ext == ".pfx",
		ext == ".jks", ext == ".kubeconfig":
		return true
	// Content-addressed objects (.../sha256/ab/abcd...) are machine artifacts —
	// manifests, lexical indexes, query signals — not human knowledge. Indexing
	// them is pure noise, and multi-MiB blobs exceed the registry object byte
	// cap, degrading status to "partial" for no real gap.
	case strings.Contains(path, "/sha256/"):
		return true
	// Lockfiles and pinned dependency closures: token-heavy, near-zero signal.
	case base == "go.sum", base == "package-lock.json", base == "pnpm-lock.yaml",
		base == "yarn.lock", base == "poetry.lock", base == "uv.lock",
		base == "Cargo.lock", base == "Gemfile.lock", base == "composer.lock",
		base == ".terraform.lock.hcl",
		strings.HasPrefix(base, "requirements") && ext == ".txt":
		return true
	// Test fixtures and vendored dependency trees are not cluster knowledge.
	case hasPathSegment(path, "testdata"), hasPathSegment(path, "vendor"),
		hasPathSegment(path, "node_modules"), hasPathSegment(path, "__pycache__"),
		hasPathSegment(path, ".venv"), hasPathSegment(path, "site-packages"):
		return true
	// Unpinned upstream scratch was never provenance-verified.
	case strings.HasPrefix(path, ".workingdir2/upstream/"):
		return true
	}
	return false
}

func isProseExtension(ext string) bool {
	return ext == ".md" || ext == ".txt" || ext == ".rst" || ext == ".adoc"
}

// isStructuredExtension covers declarative configuration: Helm values and
// templates, ArgoCD Applications, Terraform, Ansible, Packer, and the
// committed *.example templates that document them.
func isStructuredExtension(ext string) bool {
	return ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".tpl" ||
		ext == ".tf" || ext == ".tftpl" || ext == ".hcl" || ext == ".j2" ||
		ext == ".toml" || ext == ".cfg" || ext == ".conf" || ext == ".example"
}

func isSourceExtension(ext string) bool {
	return ext == ".go" || ext == ".py" || ext == ".sh" || ext == ".sql" ||
		ext == ".js" || ext == ".mjs" || ext == ".ps1"
}

func isOperationalPath(path string) bool {
	return hasRootPrefix(path, operationalRoots)
}

func isProsePath(path string) bool {
	if hasRootPrefix(path, proseRoots) {
		return true
	}
	return strings.HasPrefix(path, ".workingdir2/HANDOFF-") ||
		strings.HasPrefix(path, ".workingdir2/PLAN-") ||
		path == ".workingdir2/99-roadmap.md"
}

func hasRootPrefix(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

func hasPathSegment(path, segment string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == segment {
			return true
		}
	}
	return false
}

func isMirrorPath(path string) bool {
	path = filepath.ToSlash(path)
	for _, root := range mirrorRoots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

func prepareFileChunks(file *knowledgeFile) ([]knowledgeChunk, int, map[string]struct{}) {
	if len(file.lines) == 0 {
		return nil, 0, map[string]struct{}{}
	}
	chunks := make([]knowledgeChunk, 0, (len(file.lines)+chunkLines-chunkOverlap-1)/(chunkLines-chunkOverlap))
	fileTerms := make(map[string]struct{}, len(file.pathTerms))
	for term := range file.pathTerms {
		fileTerms[term] = struct{}{}
	}
	bodyTokens := 0
	step := chunkLines - chunkOverlap
	for start := 0; start < len(file.lines); start += step {
		end := start + chunkLines
		if end > len(file.lines) {
			end = len(file.lines)
		}
		text := strings.Join(file.lines[start:end], "\n")
		terms := termFrequency(tokenize(text))
		termCount := 0
		for _, count := range terms {
			termCount += count
		}
		bodyTokens += termCount
		for term := range terms {
			fileTerms[term] = struct{}{}
		}
		chunks = append(chunks, knowledgeChunk{
			file:      file,
			startLine: start + 1,
			endLine:   end,
			terms:     terms,
			termCount: termCount,
			weight:    pathWeight(file.path),
		})
		if end == len(file.lines) {
			break
		}
	}
	return chunks, bodyTokens, fileTerms
}

func pathWeight(path string) float64 {
	switch {
	case strings.HasPrefix(path, "knowledge/"):
		return 1.45
	case strings.HasPrefix(path, ".workingdir2/cluster-2/"):
		return 1.40
	case strings.HasPrefix(path, "docs/adr/"), strings.HasPrefix(path, "docs/runbooks/"):
		return 1.35
	case path == "STATE.md", path == "PRINCIPLES.md":
		return 1.30
	case strings.HasPrefix(path, ".workingdir2/research/"), strings.HasPrefix(path, ".workingdir2/bugs/"):
		return 1.20
	case filepath.Base(path) == "AGENTS.md":
		return 1.15
	default:
		return 1.0
	}
}

func (index *knowledgeIndex) search(query string, limit int) toolOutcome {
	if index.state == stateBackendUnavailable {
		return errorOutcome(stateBackendUnavailable, index.message, nil)
	}
	queryTerms := tokenize(query)
	if len(queryTerms) == 0 {
		return errorOutcome(stateEmpty, "query contains no searchable terms", map[string]any{"hits": []evidenceSpan{}})
	}
	queryTF := termFrequency(queryTerms)
	type scored struct {
		chunk knowledgeChunk
		score float64
	}
	scores := make([]scored, 0)
	for _, chunk := range index.chunks {
		score := index.scoreChunk(chunk, queryTF, query)
		if score > 0 {
			scores = append(scores, scored{chunk: chunk, score: score})
		}
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].score != scores[j].score {
			return scores[i].score > scores[j].score
		}
		if scores[i].chunk.file.path != scores[j].chunk.file.path {
			return scores[i].chunk.file.path < scores[j].chunk.file.path
		}
		return scores[i].chunk.startLine < scores[j].chunk.startLine
	})

	hits := make([]evidenceSpan, 0, limit)
	for _, item := range scores {
		if len(hits) == limit {
			break
		}
		if overlapsExisting(hits, item.chunk.file.path, item.chunk.startLine, item.chunk.endLine) {
			continue
		}
		snippet, truncated := boundUTF8(chunkText(item.chunk), maxSnippetBytes)
		hits = append(hits, makeEvidence(item.chunk.file, item.chunk.startLine, item.chunk.endLine, snippet, truncated, roundScore(item.score)))
	}
	if len(hits) == 0 {
		// A zero-hit search over an incomplete index cannot assert that nothing
		// matches, so it stays a typed degraded result carrying why. Over a
		// complete index zero hits remain an authoritative empty answer.
		if index.state == statePartial {
			return outcome(statePartial, index.withDegradation(map[string]any{
				"query": query, "hits": hits, "indexed_files": len(index.files),
				"result_state": stateEmpty,
			}))
		}
		return outcome(stateEmpty, map[string]any{
			"query": query, "hits": hits, "indexed_files": len(index.files),
		})
	}
	values := map[string]any{
		"query": query, "hits": hits, "indexed_files": len(index.files),
		"result_count": len(hits), "ranking": "deterministic-bm25-ish-v1",
	}
	if index.state == statePartial {
		return outcome(statePartial, index.withDegradation(values))
	}
	return outcome(stateOK, values)
}

// withDegradation attaches the exact reason an index is incomplete so a caller
// can tell a skipped-evidence result from an authoritative one.
func (index *knowledgeIndex) withDegradation(values map[string]any) map[string]any {
	values["degraded_reason"] = index.message
	values["index_warning_count"] = index.warningCount
	values["index_warning_count_exact"] = index.warningsExact
	caps := make([]knowledgeCap, 0, len(index.caps))
	for _, cap := range index.caps {
		caps = append(caps, cap)
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i].Resource < caps[j].Resource })
	values["index_caps"] = caps
	return values
}

func (index *knowledgeIndex) scoreChunk(chunk knowledgeChunk, query map[string]int, rawQuery string) float64 {
	if len(index.chunks) == 0 || index.avgTerms == 0 {
		return 0
	}
	const k1 = 1.2
	const b = 0.75
	score := 0.0
	for term, queryCount := range query {
		tf := chunk.terms[term]
		pathTF := chunk.file.pathTerms[term]
		if tf == 0 && pathTF == 0 {
			continue
		}
		df := index.df[term]
		idf := math.Log(1 + (float64(len(index.chunks)-df)+0.5)/(float64(df)+0.5))
		body := 0.0
		if tf > 0 {
			body = (float64(tf) * (k1 + 1)) / (float64(tf) + k1*(1-b+b*float64(chunk.termCount)/index.avgTerms))
		}
		score += idf * (body + 1.8*float64(pathTF)) * float64(queryCount)
	}
	phrase := strings.ToLower(strings.TrimSpace(rawQuery))
	if len(phrase) >= 3 && strings.Contains(strings.ToLower(chunkText(chunk)), phrase) {
		score += 4.0
	}
	return score * chunk.weight
}

func chunkText(chunk knowledgeChunk) string {
	return strings.Join(chunk.file.lines[chunk.startLine-1:chunk.endLine], "\n")
}

func (index *knowledgeIndex) get(path string, startLine, endLine int) toolOutcome {
	normalized, err := normalizeRequestedPath(path)
	if err != nil {
		return errorOutcome(stateForbidden, err.Error(), map[string]any{"path": path})
	}
	file, ok := index.files[normalized]
	if !ok {
		return errorOutcome(stateForbidden, "path is not an indexed high-signal tracked file", map[string]any{"path": normalized})
	}
	if startLine > len(file.lines) {
		return outcome(stateEmpty, map[string]any{"path": normalized, "line_count": len(file.lines)})
	}
	if endLine == 0 || endLine > len(file.lines) {
		endLine = len(file.lines)
	}
	if endLine < startLine {
		return errorOutcome(stateEmpty, "end_line must be greater than or equal to start_line", map[string]any{"path": normalized})
	}
	if endLine-startLine+1 > 500 {
		endLine = startLine + 499
	}
	snippet := strings.Join(file.lines[startLine-1:endLine], "\n")
	snippet, truncated := boundUTF8(snippet, 64<<10)
	evidence := makeEvidence(file, startLine, endLine, snippet, truncated, 0)
	state := stateOK
	if truncated || endLine < len(file.lines) || index.state == statePartial {
		state = statePartial
	}
	return outcome(state, map[string]any{
		"evidence": evidence, "line_count": len(file.lines), "size_bytes": file.size,
	})
}

func (index *knowledgeIndex) context(query string, limit, maxChars int) toolOutcome {
	search := index.search(query, limit)
	if search.State == stateBackendUnavailable || search.State == stateEmpty || search.Error {
		return search
	}
	// A degraded zero-hit search keeps its typed partial/empty pair rather than
	// being rebuilt into a context that looks like a complete no-match answer.
	if resultState, ok := search.Data["result_state"].(typedState); ok && resultState == stateEmpty {
		return search
	}
	rawHits, _ := search.Data["hits"].([]evidenceSpan)
	hits := make([]evidenceSpan, 0, len(rawHits))
	var builder strings.Builder
	truncated := false
	for _, hit := range rawHits {
		header := fmt.Sprintf("[%s:%d-%d %s %s]\n", hit.Path, hit.StartLine, hit.EndLine, hit.SHA256, hit.ProvenanceClass)
		piece := header + hit.Snippet + "\n"
		remaining := maxChars - builder.Len()
		if remaining <= 0 {
			truncated = true
			break
		}
		if len(piece) > remaining {
			piece, _ = boundUTF8(piece, remaining)
			truncated = true
		}
		builder.WriteString(piece)
		hits = append(hits, hit)
		if truncated {
			break
		}
	}
	state := search.State
	if truncated {
		state = statePartial
	}
	return outcome(state, map[string]any{
		"query": query, "context": strings.TrimSuffix(builder.String(), "\n"),
		"evidence": hits, "truncated": truncated,
	})
}

func makeEvidence(file *knowledgeFile, start, end int, snippet string, truncated bool, score float64) evidenceSpan {
	identity := fmt.Sprintf("%s\x00%s\x00%d\x00%d", file.path, file.hash, start, end)
	digest := sha256.Sum256([]byte(identity))
	return evidenceSpan{
		AuthorityClass:        file.authorityClass,
		ContentBinding:        "sha256_of_worktree_bytes_at_mcp_index_time",
		ContentRole:           "untrusted_data_only",
		EvidenceID:            "evi-" + hex.EncodeToString(digest[:12]),
		InstructionsForbidden: true,
		Path:                  file.path,
		ProvenanceClass:       file.provenanceClass,
		StartLine:             start,
		EndLine:               end,
		SHA256:                file.hash,
		Snippet:               snippet,
		Score:                 score,
		Truncated:             truncated,
	}
}

func readSafeRelative(root, relative string, maxBytes int64) ([]byte, error) {
	normalized, err := normalizeRequestedPath(relative)
	if err != nil {
		return nil, err
	}
	current := root
	for _, part := range strings.Split(normalized, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink paths are forbidden")
		}
	}
	return readBoundRegular(current, maxBytes, true)
}

func normalizeRequestedPath(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, '\x00') || filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return "", fmt.Errorf("absolute, empty, NUL, and backslash paths are forbidden")
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("path traversal and non-canonical paths are forbidden")
		}
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean != path {
		return "", fmt.Errorf("path must be canonical")
	}
	return clean, nil
}

func tokenize(value string) []string {
	terms := make([]string, 0)
	var builder strings.Builder
	flush := func() {
		if builder.Len() > 1 {
			terms = append(terms, builder.String())
		}
		builder.Reset()
	}
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			builder.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return terms
}

func termFrequency(terms []string) map[string]int {
	result := make(map[string]int, len(terms))
	for _, term := range terms {
		result[term]++
	}
	return result
}

func splitLines(value string) []string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.TrimSuffix(value, "\n")
	if value == "" {
		return []string{}
	}
	return strings.Split(value, "\n")
}

func bytesLookBinary(value []byte) bool {
	limit := len(value)
	if limit > 8192 {
		limit = 8192
	}
	for _, b := range value[:limit] {
		if b == 0 {
			return true
		}
	}
	return false
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func boundUTF8(value string, maximum int) (string, bool) {
	if maximum < 0 {
		maximum = 0
	}
	if len(value) <= maximum {
		return value, false
	}
	value = value[:maximum]
	for !utf8.ValidString(value) && len(value) > 0 {
		value = value[:len(value)-1]
	}
	return value, true
}

func overlapsExisting(hits []evidenceSpan, path string, start, end int) bool {
	for _, hit := range hits {
		if hit.Path == path && start <= hit.EndLine && end >= hit.StartLine {
			return true
		}
	}
	return false
}

func roundScore(value float64) float64 {
	return math.Round(value*1_000_000) / 1_000_000
}
