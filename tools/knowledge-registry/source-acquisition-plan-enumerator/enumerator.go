package main

// Tree-chain enumerator: authors a v3 acquisition plan by walking, for each
// selected file, the tag -> commit -> every intermediate tree edge -> blob
// closure over the GitHub Git-object REST API and, for every object,
// reconstructing and verifying the Git 'blob <n>\0<raw>' SHA-1, the raw
// SHA-256, and the byte count.
//
// The REST client (getJSON), the tree fetch/guard (getTree), and the canonical
// tree-entry selector (exactTreeEntry) are reused VERBATIM from the frozen
// P1-SRC-03 runner (runner.go:508-777). The enumerate* functions replace
// P1-SRC-03's "verify against a frozen contract" walk with a "discover and
// record" walk, keeping every fail-closed proof: the redirect ban, the
// pagination-Link ban, the single-content-type identity check, the response
// byte bounds, the non-recursive tree descent with tree-cycle rejection, the
// annotated-tag chain bound and cycle rejection, and the Git-object SHA-1
// reconstruction. A blob whose bytes do not reproduce the SHA-1 the tree edge
// declared fails closed — a tampered blob cannot be enumerated into a plan.

import (
	"context"
	"crypto/sha1" // #nosec G505 -- Git blob object identifiers require SHA-1; content integrity is also bound by SHA-256.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	enumeratorName    = "archeion-source-acquisition-plan-enumerator"
	enumeratorVersion = "1"
)

type enumerator struct {
	client        *http.Client
	baseURL       *url.URL
	token         string
	allowedRepos  map[string]struct{}
	requests      int
	responseBytes int64
	treeCache     map[string]gitTree
}

type gitObject struct {
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type gitRef struct {
	Ref    string    `json:"ref"`
	Object gitObject `json:"object"`
}

type gitTag struct {
	Tag    string    `json:"tag"`
	SHA    string    `json:"sha"`
	Object gitObject `json:"object"`
}

type gitCommit struct {
	SHA  string `json:"sha"`
	Tree struct {
		SHA string `json:"sha"`
	} `json:"tree"`
}

type gitTree struct {
	SHA       string         `json:"sha"`
	Tree      []gitTreeEntry `json:"tree"`
	Truncated *bool          `json:"truncated"`
}

type gitTreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size *int64 `json:"size,omitempty"`
}

type gitBlob struct {
	SHA      string `json:"sha"`
	Size     *int64 `json:"size"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

// fileSelection is the operator-supplied selection of one file to enumerate.
type fileSelection struct {
	SourceKey string `json:"source_key"`
	Path      string `json:"path"`
}

// targetRequest pins one authority: a repository, a ref (annotated/lightweight
// tag by default, or a branch HEAD when ref_kind is "branch"), the expected
// commit that ref must resolve to, and the selected file paths. ref_kind is
// absent or "tag" for the tag path (byte-identical to prior contracts) or
// "branch" to resolve an untagged repo's branch head.
type targetRequest struct {
	AuthorityID        string          `json:"authority_id"`
	SourceSetID        string          `json:"source_set_id"`
	ComponentID        string          `json:"component_id"`
	ComponentVersion   string          `json:"component_version"`
	Repository         string          `json:"repository"`
	Publisher          publisher       `json:"publisher"`
	LicenseExpression  string          `json:"license_expression"`
	RequestedTag       string          `json:"requested_tag"`
	RefKind            string          `json:"ref_kind,omitempty"`
	ExpectedCommitSHA1 string          `json:"expected_commit_sha1"`
	Files              []fileSelection `json:"files"`
}

// planRequest is the complete enumeration input for one contract.
//
// Beyond the per-target selections it carries the top-level spec inputs the
// runner's contract requires but the enumerator stays decoupled from:
//   - freeze_id / freeze_document_sha256 -> the comparison-only source_denominator.
//   - execution_manifest_id / execution_manifest_payload_sha256 -> the
//     execution_gate binding. These MUST equal the runner's embedded
//     execution-manifest.json (source-acquisition-runner-v3/execution-manifest.json):
//     id "source-acquisition-execution-manifest:sha256:77408c9e73350efb068c17863b2282ce1db44c2d9ca3075e26bcff7149241690"
//     and payload sha256 "sha256:77408c9e73350efb068c17863b2282ce1db44c2d9ca3075e26bcff7149241690",
//     or the runner rejects the emitted contract's execution gate.
type planRequest struct {
	WorkID                         string          `json:"work_id"`
	FreezeID                       string          `json:"freeze_id"`
	FreezeDocumentSHA256           string          `json:"freeze_document_sha256"`
	ExecutionManifestID            string          `json:"execution_manifest_id"`
	ExecutionManifestPayloadSHA256 string          `json:"execution_manifest_payload_sha256"`
	Targets                        []targetRequest `json:"targets"`
}

func newEnumerator(client *http.Client, baseURL, token string, allowTestOrigin bool, request planRequest) (*enumerator, error) {
	if client == nil {
		return nil, errors.New("HTTP client is required")
	}
	if err := validatePlanRequest(request); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse API origin: %w", err)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" || parsed.User != nil || parsed.ForceQuery || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" || parsed.Host == "" {
		return nil, errors.New("API origin must contain only scheme and authority")
	}
	if !allowTestOrigin && parsed.String() != apiOrigin {
		return nil, errors.New("production API origin differs from the exact capability")
	}
	if !allowTestOrigin && parsed.Scheme != "https" {
		return nil, errors.New("production enumerator requires HTTPS")
	}
	if allowTestOrigin && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("test API origin requires HTTP or HTTPS")
	}
	if !validTokenHeaderValue(token) {
		return nil, errors.New("GitHub token is not a bounded single-line header value")
	}
	clientCopy := *client
	clientCopy.Jar = nil
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("redirects are forbidden for exact Git-object enumeration")
	}
	allowed := make(map[string]struct{}, len(request.Targets))
	for _, target := range request.Targets {
		allowed[target.Repository] = struct{}{}
	}
	parsed.Path = ""
	return &enumerator{client: &clientCopy, baseURL: parsed, token: token, allowedRepos: allowed, treeCache: map[string]gitTree{}}, nil
}

func validatePlanRequest(request planRequest) error {
	if request.WorkID == "" || !utf8.ValidString(request.WorkID) || len(request.WorkID) > 256 || strings.TrimSpace(request.WorkID) != request.WorkID {
		return errors.New("plan request work identity is empty or over-bound")
	}
	// Top-level spec inputs for the runner's source_denominator and execution_gate.
	// The enumerator validates only their SHAPE; the runner enforces that the
	// execution-gate values equal its embedded execution manifest byte-for-byte.
	if request.FreezeID == "" || !utf8.ValidString(request.FreezeID) || len(request.FreezeID) > 512 {
		return errors.New("plan request freeze id is empty or over-bound")
	}
	if !validSHA256(request.FreezeDocumentSHA256) {
		return errors.New("plan request freeze document sha256 is not a canonical sha256")
	}
	if request.ExecutionManifestID == "" || !utf8.ValidString(request.ExecutionManifestID) || len(request.ExecutionManifestID) > 512 {
		return errors.New("plan request execution manifest id is empty or over-bound")
	}
	if !validSHA256(request.ExecutionManifestPayloadSHA256) {
		return errors.New("plan request execution manifest payload sha256 is not a canonical sha256")
	}
	if len(request.Targets) == 0 || len(request.Targets) > maxPlanTargets {
		return errors.New("plan request target cardinality is empty or over-bound")
	}
	seenAuthorities := map[string]struct{}{}
	seenSets := map[string]struct{}{}
	seenPublishers := map[string]struct{}{}
	seenRepos := map[string]struct{}{}
	totalFiles := 0
	for _, target := range request.Targets {
		if target.AuthorityID == "" || target.SourceSetID == "" || target.ComponentID == "" || target.ComponentVersion == "" || target.Publisher.PublisherID == "" || target.LicenseExpression == "" {
			return errors.New("plan request target identity is incomplete")
		}
		if _, ok := seenAuthorities[target.AuthorityID]; ok {
			return errors.New("plan request aliases source authorities")
		}
		if _, ok := seenSets[target.SourceSetID]; ok {
			return errors.New("plan request aliases source sets")
		}
		if _, ok := seenPublishers[target.Publisher.PublisherID]; ok {
			return errors.New("plan request aliases publishers")
		}
		if _, ok := seenRepos[target.Repository]; ok {
			return errors.New("plan request aliases repositories")
		}
		seenAuthorities[target.AuthorityID] = struct{}{}
		seenSets[target.SourceSetID] = struct{}{}
		seenPublishers[target.Publisher.PublisherID] = struct{}{}
		seenRepos[target.Repository] = struct{}{}
		if !repoPattern.MatchString(target.Repository) || len(target.Repository) > 512 {
			return errors.New("plan request repository syntax is invalid")
		}
		if !validRequestedRef(target.RefKind, target.RequestedTag) || !sha1Pattern.MatchString(target.ExpectedCommitSHA1) {
			return errors.New("plan request ref kind, ref name, or expected commit is malformed")
		}
		if len(target.Files) == 0 {
			return errors.New("plan request target selects no files")
		}
		seenPaths := map[string]struct{}{}
		for _, file := range target.Files {
			if file.SourceKey == "" || !utf8.ValidString(file.SourceKey) || len(file.SourceKey) > 256 {
				return errors.New("plan request file source key is empty or over-bound")
			}
			if err := validatePath(file.Path); err != nil {
				return err
			}
			if _, ok := seenPaths[file.Path]; ok {
				return errors.New("plan request duplicates a source path")
			}
			seenPaths[file.Path] = struct{}{}
			totalFiles++
		}
	}
	if totalFiles > maxPlanFiles {
		return errors.New("plan request file cardinality is over-bound")
	}
	return nil
}

func validTokenHeaderValue(token string) bool {
	if len(token) > maxTokenBytes || !utf8.ValidString(token) || strings.TrimSpace(token) != token {
		return false
	}
	for _, value := range []byte(token) {
		if value <= 0x20 || value == 0x7f {
			return false
		}
	}
	return true
}

// enumerate walks every target and authors the complete v3 plan.
func (e *enumerator) enumerate(ctx context.Context, request planRequest) (acquisitionPlan, []byte, error) {
	if err := validatePlanRequest(request); err != nil {
		return acquisitionPlan{}, nil, err
	}
	e.requests = 0
	e.responseBytes = 0
	e.treeCache = map[string]gitTree{}
	targets := make([]contractTarget, 0, len(request.Targets))
	for _, target := range request.Targets {
		enumerated, err := e.enumerateTarget(ctx, target)
		if err != nil {
			return acquisitionPlan{}, nil, fmt.Errorf("enumerate %s: %w", target.AuthorityID, err)
		}
		targets = append(targets, enumerated)
	}
	core := planCore{
		Schema: contractSchema, SchemaVersion: contractSchemaVersion, Canonicalization: canonicalProfile, ContractKind: contractKind, WorkID: request.WorkID,
		AuthorityState: contractAuthorityState, ReviewState: contractReviewState, CompileEligible: false, PromoteEligible: false, AuthorityBoundary: authorityBoundary{},
		SourceDenominator:     sourceDenominator{FreezeID: request.FreezeID, FreezeDocumentSHA256: request.FreezeDocumentSHA256, ComparisonOnly: true},
		AcquisitionCapability: planCapability(),
		ExecutionGate: executionGate{
			ManifestID: request.ExecutionManifestID, ManifestPayloadSHA256: request.ExecutionManifestPayloadSHA256,
			VerificationState: executionVerificationState, ExternalVerificationRequired: true, Verified: false, PredecessorEligible: false,
		},
		Bounds: planBounds(targets), Targets: targets,
	}
	return materializePlan(core)
}

func (e *enumerator) enumerateTarget(ctx context.Context, request targetRequest) (contractTarget, error) {
	var (
		refType string
		refSHA  string
		chain   []expectedTagObject
		err     error
	)
	switch request.RefKind {
	case "branch":
		refType, refSHA, chain, err = e.enumerateBranch(ctx, request.Repository, request.RequestedTag, request.ExpectedCommitSHA1)
	case "", "tag":
		refType, refSHA, chain, err = e.enumerateTag(ctx, request.Repository, request.RequestedTag, request.ExpectedCommitSHA1)
	default:
		return contractTarget{}, errors.New("target ref kind is neither tag nor branch")
	}
	if err != nil {
		return contractTarget{}, err
	}
	rootTree, err := e.enumerateCommit(ctx, request.Repository, request.ExpectedCommitSHA1)
	if err != nil {
		return contractTarget{}, err
	}
	files := make([]contractFile, 0, len(request.Files))
	for _, selection := range request.Files {
		bindings, blobSHA, mode, treeSize, err := e.enumeratePath(ctx, request.Repository, rootTree, selection.Path)
		if err != nil {
			return contractTarget{}, fmt.Errorf("resolve %s: %w", selection.Path, err)
		}
		rawSHA256, size, err := e.enumerateBlob(ctx, request.Repository, blobSHA, treeSize)
		if err != nil {
			return contractTarget{}, fmt.Errorf("blob %s: %w", selection.Path, err)
		}
		files = append(files, contractFile{
			SourceKey: selection.SourceKey, Path: selection.Path, Mode: mode, GitBlobSHA1: blobSHA,
			RawSHA256: rawSHA256, Bytes: size, ExpectedPathResolution: bindings,
		})
	}
	core := contractTargetCore{
		AuthorityID: request.AuthorityID, SourceSetID: request.SourceSetID, ComponentID: request.ComponentID, ComponentVersion: request.ComponentVersion,
		Repository: request.Repository, Publisher: request.Publisher, LicenseExpression: request.LicenseExpression, RequestedTag: request.RequestedTag, RefKind: request.RefKind,
		ExpectedRefType: refType, ExpectedRefSHA1: refSHA, ExpectedTagObjects: chain, ExpectedCommitSHA1: request.ExpectedCommitSHA1, ExpectedRootTreeSHA1: rootTree, Files: files,
	}
	targetID, err := deriveTargetID(core)
	if err != nil {
		return contractTarget{}, err
	}
	return contractTarget{TargetID: targetID, contractTargetCore: core}, nil
}

// enumerateTag resolves the pinned tag by discovery: it reads the tag ref, then
// follows the annotated-tag chain (bounded, cycle-rejecting) until it reaches a
// commit, asserting that commit is exactly the pinned commit. It records the
// discovered ref object and the full annotated-tag chain.
func (e *enumerator) enumerateTag(ctx context.Context, repository, tag, expectedCommit string) (string, string, []expectedTagObject, error) {
	if !tagPattern.MatchString(tag) {
		return "", "", nil, errors.New("tag is outside the exact syntax")
	}
	if !sha1Pattern.MatchString(expectedCommit) {
		return "", "", nil, errors.New("expected commit is not a canonical SHA-1")
	}
	var reference gitRef
	if err := e.getJSON(ctx, repository, "/git/ref/tags/"+url.PathEscape(tag), &reference); err != nil {
		return "", "", nil, fmt.Errorf("get exact tag ref: %w", err)
	}
	if reference.Ref != "refs/tags/"+tag {
		return "", "", nil, errors.New("tag ref name drifted from the requested tag")
	}
	if (reference.Object.Type != "tag" && reference.Object.Type != "commit") || !sha1Pattern.MatchString(reference.Object.SHA) {
		return "", "", nil, errors.New("tag ref object type or SHA is invalid")
	}
	refType := reference.Object.Type
	refSHA := reference.Object.SHA
	chain := []expectedTagObject{}
	current := reference.Object
	seenTags := map[string]struct{}{}
	for current.Type == "tag" {
		if len(chain) >= maxAnnotatedTagChain {
			return "", "", nil, errors.New("annotated tag chain exceeds the object bound")
		}
		if _, ok := seenTags[current.SHA]; ok {
			return "", "", nil, errors.New("annotated tag chain contains a cycle")
		}
		seenTags[current.SHA] = struct{}{}
		var annotated gitTag
		if err := e.getJSON(ctx, repository, "/git/tags/"+current.SHA, &annotated); err != nil {
			return "", "", nil, err
		}
		if annotated.SHA != current.SHA || !sha1Pattern.MatchString(annotated.Object.SHA) {
			return "", "", nil, errors.New("annotated tag object identity drifted")
		}
		if annotated.Object.Type != "tag" && annotated.Object.Type != "commit" {
			return "", "", nil, errors.New("annotated tag points at neither a tag nor a commit")
		}
		if len(chain) == 0 && annotated.Tag != tag {
			return "", "", nil, errors.New("first annotated tag name differs from the requested tag")
		}
		chain = append(chain, expectedTagObject{SHA1: annotated.SHA, Name: annotated.Tag, TargetType: annotated.Object.Type, TargetSHA1: annotated.Object.SHA})
		current = annotated.Object
	}
	if current.Type != "commit" || current.SHA != expectedCommit {
		return "", "", nil, errors.New("tag does not terminate at the pinned commit")
	}
	return refType, refSHA, chain, nil
}

// enumerateBranch resolves a pinned branch by discovery: it reads the branch
// HEAD ref through the SAME redirect-banned client and asserts the head commit
// is exactly the pinned commit. A branch carries no annotated-tag chain, so it
// binds the commit directly (refType "commit", empty chain) exactly like the
// lightweight-tag path — the commit machinery downstream is unchanged.
func (e *enumerator) enumerateBranch(ctx context.Context, repository, branch, expectedCommit string) (string, string, []expectedTagObject, error) {
	if !validBranchName(branch) {
		return "", "", nil, errors.New("branch is outside the exact syntax")
	}
	if !sha1Pattern.MatchString(expectedCommit) {
		return "", "", nil, errors.New("expected commit is not a canonical SHA-1")
	}
	var reference gitRef
	if err := e.getJSON(ctx, repository, "/git/ref/heads/"+url.PathEscape(branch), &reference); err != nil {
		return "", "", nil, fmt.Errorf("get exact branch ref: %w", err)
	}
	if reference.Ref != "refs/heads/"+branch {
		return "", "", nil, errors.New("branch ref name drifted from the requested branch")
	}
	if reference.Object.Type != "commit" || !sha1Pattern.MatchString(reference.Object.SHA) {
		return "", "", nil, errors.New("branch ref object type or SHA is invalid")
	}
	if reference.Object.SHA != expectedCommit {
		return "", "", nil, errors.New("branch head does not resolve to the pinned commit")
	}
	return "commit", expectedCommit, []expectedTagObject{}, nil
}

// enumerateCommit reads the pinned commit and records its root tree.
func (e *enumerator) enumerateCommit(ctx context.Context, repository, commitSHA string) (string, error) {
	var commit gitCommit
	if err := e.getJSON(ctx, repository, "/git/commits/"+commitSHA, &commit); err != nil {
		return "", err
	}
	if commit.SHA != commitSHA || !sha1Pattern.MatchString(commit.Tree.SHA) {
		return "", errors.New("commit identity or root tree drifted")
	}
	return commit.Tree.SHA, nil
}

// enumeratePath walks a file path non-recursively from the root tree, recording
// every intermediate tree edge and the terminal blob edge. Intermediate objects
// must be trees (mode 040000, no size) and no tree may repeat (cycle rejection).
func (e *enumerator) enumeratePath(ctx context.Context, repository, rootTree, path string) ([]pathBinding, string, string, int64, error) {
	if err := validatePath(path); err != nil {
		return nil, "", "", 0, err
	}
	segments := strings.Split(path, "/")
	current := rootTree
	bindings := make([]pathBinding, 0, len(segments))
	seenTrees := map[string]struct{}{rootTree: {}}
	for index, segment := range segments {
		tree, err := e.getTree(ctx, repository, current)
		if err != nil {
			return nil, "", "", 0, err
		}
		entry, err := exactTreeEntry(tree.Tree, segment)
		if err != nil {
			return nil, "", "", 0, err
		}
		last := index == len(segments)-1
		if !last {
			if entry.Type != "tree" || entry.Mode != "040000" || entry.Size != nil {
				return nil, "", "", 0, errors.New("exact path segment is not a Git tree")
			}
			if _, exists := seenTrees[entry.SHA]; exists {
				return nil, "", "", 0, errors.New("tree cycle in exact source path")
			}
			seenTrees[entry.SHA] = struct{}{}
			bindings = append(bindings, pathBinding{ParentTreeSHA1: current, Segment: segment, ObjectType: entry.Type, Mode: entry.Mode, ObjectSHA1: entry.SHA})
			current = entry.SHA
			continue
		}
		if entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") || entry.Size == nil || *entry.Size < 0 {
			return nil, "", "", 0, errors.New("exact terminal path segment is not a Git blob")
		}
		size := *entry.Size
		bindings = append(bindings, pathBinding{ParentTreeSHA1: current, Segment: segment, ObjectType: entry.Type, Mode: entry.Mode, ObjectSHA1: entry.SHA, Bytes: &size})
		return bindings, entry.SHA, entry.Mode, size, nil
	}
	return nil, "", "", 0, errors.New("path resolution produced no terminal blob")
}

// enumerateBlob fetches a blob and proves its bytes reproduce the Git SHA-1 the
// tree edge declared. A tampered blob whose content hashes to a different SHA-1
// fails here. It records the raw SHA-256 and byte count.
func (e *enumerator) enumerateBlob(ctx context.Context, repository, blobSHA string, expectedSize int64) (string, int64, error) {
	if !sha1Pattern.MatchString(blobSHA) {
		return "", 0, errors.New("blob SHA-1 is not canonical")
	}
	if expectedSize < 0 || expectedSize > maxBlobBytes {
		return "", 0, errors.New("declared blob size is negative or over-bound")
	}
	var blob gitBlob
	if err := e.getJSON(ctx, repository, "/git/blobs/"+blobSHA, &blob); err != nil {
		return "", 0, err
	}
	if blob.SHA != blobSHA || blob.Size == nil || *blob.Size != expectedSize || blob.Encoding != "base64" {
		return "", 0, errors.New("blob response identity, encoding, or size drifted")
	}
	return decodeGitBlob(blob.Content, blobSHA, expectedSize)
}

func decodeGitBlob(content, blobSHA string, expectedSize int64) (string, int64, error) {
	compact := strings.NewReplacer("\n", "", "\r", "").Replace(content)
	raw, err := base64.StdEncoding.Strict().DecodeString(compact)
	if err != nil {
		return "", 0, errors.New("blob content is not strict base64")
	}
	if int64(len(raw)) != expectedSize {
		return "", 0, errors.New("decoded blob size drifted from the tree edge")
	}
	identity := append([]byte("blob "+strconv.Itoa(len(raw))+"\x00"), raw...)
	gitDigest := sha1.Sum(identity) // #nosec G401 -- Reconstruct the protocol-defined Git blob SHA-1 identity; SHA-256 separately binds the artifact bytes.
	if hex.EncodeToString(gitDigest[:]) != blobSHA {
		return "", 0, errors.New("decoded blob does not reproduce the declared Git SHA-1")
	}
	rawDigest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(rawDigest[:]), int64(len(raw)), nil
}

func (e *enumerator) getTree(ctx context.Context, repository, sha string) (gitTree, error) {
	key := repository + ":" + sha
	if cached, ok := e.treeCache[key]; ok {
		return cached, nil
	}
	var tree gitTree
	if err := e.getJSON(ctx, repository, "/git/trees/"+sha, &tree); err != nil {
		return gitTree{}, err
	}
	if tree.SHA != sha || tree.Truncated == nil || *tree.Truncated || len(tree.Tree) > maxTreeEntries {
		return gitTree{}, errors.New("tree response is swapped, truncated, or over-bound")
	}
	if _, err := exactTreeEntry(tree.Tree, "__archeion_nonexistent_probe__"); err != nil && !strings.Contains(err.Error(), "no exact requested child") {
		return gitTree{}, err
	}
	e.treeCache[key] = tree
	return tree, nil
}

// getJSON performs one bounded, redirect-forbidden, single-content-type GET.
// Reused VERBATIM from P1-SRC-03 runner.go (only the User-Agent string differs).
func (e *enumerator) getJSON(ctx context.Context, repository, suffix string, destination any) (err error) {
	if _, ok := e.allowedRepos[repository]; !ok {
		return errors.New("repository is outside the plan-request denominator")
	}
	if e.requests >= maxHTTPRequests || !strings.HasPrefix(suffix, "/git/") || strings.ContainsAny(suffix, "?#") {
		return errors.New("HTTP request is outside the exact capability")
	}
	endpoint := e.baseURL.String() + "/repos/" + repository + suffix
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) // #nosec G704 -- newEnumerator pins the production API origin to api.github.com and forbids redirects before sending; alternate origins require explicit test mode.
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	request.Header.Set("User-Agent", enumeratorName+"/"+enumeratorVersion)
	request.Header.Set("Accept-Encoding", "identity")
	if e.token != "" {
		request.Header.Set("Authorization", "Bearer "+e.token)
	}
	e.requests++
	response, err := e.client.Do(request) // #nosec G704 -- newEnumerator pins the production API origin to api.github.com and forbids redirects before sending; alternate origins require explicit test mode.
	if err != nil {
		return err
	}
	defer func() { err = closeWithError(err, response.Body) }()
	return e.readGitObjectResponse(response, endpoint, destination)
}

func (e *enumerator) readGitObjectResponse(response *http.Response, endpoint string, destination any) error {
	if err := validateGitObjectResponse(response, endpoint); err != nil {
		return err
	}
	remaining := maxResponseBytes - e.responseBytes
	if remaining <= 0 {
		return errors.New("HTTP response byte bound exceeded")
	}
	limit := maxObjectJSONBytes
	if remaining < limit {
		limit = remaining
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return errors.New("Git-object response exceeds byte bound")
	}
	e.responseBytes += int64(len(raw))
	if _, err := parseStrictJSON(raw); err != nil {
		return fmt.Errorf("strict Git-object JSON: %w", err)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return err
	}
	return nil
}

// exactTreeEntry selects one canonical tree child. Reused VERBATIM from
// P1-SRC-03 runner.go.
func validateGitObjectResponse(response *http.Response, endpoint string) error {
	if err := gitObjectStatusError(response); err != nil {
		return err
	}

	if response.Request == nil || response.Request.URL.String() != endpoint {
		return errors.New("Git-object response arrived through a redirected or changed endpoint")
	}
	if len(response.Header.Values("Link")) != 0 {
		return errors.New("Git-object endpoint returned a pagination Link header")
	}
	encodings := response.Header.Values("Content-Encoding")
	if len(encodings) > 1 || (len(encodings) == 1 && encodings[0] != "identity") {
		return errors.New("Git-object response used an unexpected content encoding")
	}
	return validateGitObjectContentType(response)
}

func validateGitObjectContentType(response *http.Response) error {
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return errors.New("Git-object response has an ambiguous or missing content type")
	}
	contentType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || contentType != "application/json" {
		return errors.New("Git-object response is not application/json")
	}

	return nil
}

func gitObjectStatusError(response *http.Response) error {
	if response.StatusCode != http.StatusOK {
		_, drainErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if drainErr != nil {
			drainErr = fmt.Errorf("drain Git-object error response: %w", drainErr)
		}
		return errors.Join(fmt.Errorf("GitHub REST returned HTTP %d", response.StatusCode), drainErr)
	}
	return nil
}

func exactTreeEntry(entries []gitTreeEntry, name string) (gitTreeEntry, error) {
	seen := make(map[string]struct{}, len(entries))
	var match *gitTreeEntry
	for index := range entries {
		entry := entries[index]
		if entry.Path == "" || entry.Path == "." || entry.Path == ".." || strings.ContainsAny(entry.Path, "/\x00\r\n") || !utf8.ValidString(entry.Path) || !sha1Pattern.MatchString(entry.SHA) {
			return gitTreeEntry{}, errors.New("tree contains a noncanonical entry")
		}
		if _, ok := seen[entry.Path]; ok {
			return gitTreeEntry{}, errors.New("tree contains duplicate paths")
		}
		seen[entry.Path] = struct{}{}
		if entry.Path == name {
			copy := entry
			match = &copy
		}
	}
	if match == nil {
		return gitTreeEntry{}, errors.New("tree has no exact requested child")
	}
	return *match, nil
}
