package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// suiteFreeze is the frozen acceptance-suite document. Fixture pins make every
// case fail closed when any fixture byte drifts from the freeze.
type suiteFreeze struct {
	SchemaVersion  string                  `json:"schema_version"`
	RecordKind     string                  `json:"record_kind"`
	SuiteID        string                  `json:"suite_id"`
	Revision       string                  `json:"revision"`
	FrozenAt       string                  `json:"frozen_at"`
	Issue          string                  `json:"issue"`
	BrokerContract suiteBrokerContract     `json:"broker_contract"`
	Cases          []suiteCase             `json:"cases"`
	Fixtures       map[string]suiteFixture `json:"fixtures"`
	Normalization  suiteNormalization      `json:"normalization"`
}

type suiteBrokerContract struct {
	ServerName      string `json:"server_name"`
	ServerVersion   string `json:"server_version"`
	ProtocolVersion string `json:"protocol_version"`
	ToolCount       int    `json:"tool_count"`
}

type suiteCase struct {
	CaseID           string   `json:"case_id"`
	CaseClass        string   `json:"case_class"`
	ExecutionSurface []string `json:"execution_surface"`
	Proves           string   `json:"proves"`
}

type suiteFixture struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type suiteNormalization struct {
	VolatileFields []string `json:"volatile_fields"`
	Replacement    string   `json:"replacement"`
	WorkspaceToken string   `json:"workspace_token"`
}

var frozenCaseClasses = []string{
	"success", "stale", "one_lane_timeout", "tamper", "conflict",
	"acl", "deletion", "pagination", "reconnect", "deterministic_order",
}

func loadSuite(suiteDir string) (*suiteFreeze, error) {
	raw, err := os.ReadFile(filepath.Join(suiteDir, "suite-freeze.json"))
	if err != nil {
		return nil, fmt.Errorf("read suite freeze: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var freeze suiteFreeze
	if err := decoder.Decode(&freeze); err != nil {
		return nil, fmt.Errorf("decode suite freeze: %w", err)
	}
	if freeze.SchemaVersion != "1.0.0" || freeze.RecordKind != "mcp01_acceptance_suite_freeze" {
		return nil, errors.New("suite freeze schema_version or record_kind is unsupported")
	}
	if len(freeze.Cases) != len(frozenCaseClasses) {
		return nil, fmt.Errorf("suite freeze must declare exactly %d cases", len(frozenCaseClasses))
	}
	declared := make(map[string]struct{}, len(freeze.Cases))
	for _, frozenCase := range freeze.Cases {
		declared[frozenCase.CaseClass] = struct{}{}
	}
	for _, class := range frozenCaseClasses {
		if _, exists := declared[class]; !exists {
			return nil, fmt.Errorf("suite freeze is missing the frozen case class %q", class)
		}
	}
	if len(freeze.Fixtures) == 0 {
		return nil, errors.New("suite freeze pins no fixtures")
	}
	return &freeze, nil
}

func hashFile(path string) (string, int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), int64(len(raw)), nil
}

// verifyFixturePins re-hashes every pinned fixture and rejects unpinned
// stragglers, so a single mutated or planted byte fails the whole suite closed.
func verifyFixturePins(suiteDir string, freeze *suiteFreeze) error {
	seen := make(map[string]struct{}, len(freeze.Fixtures))
	for relative, pin := range freeze.Fixtures {
		digest, size, err := hashFile(filepath.Join(suiteDir, relative))
		if err != nil {
			return fmt.Errorf("fixture %s: %w", relative, err)
		}
		if digest != pin.SHA256 || size != pin.Bytes {
			return fmt.Errorf("fixture %s does not match its frozen pin (got sha256:%s, %d bytes)", relative, digest, size)
		}
		seen[relative] = struct{}{}
	}
	fixturesRoot := filepath.Join(suiteDir, "fixtures")
	return filepath.WalkDir(fixturesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(suiteDir, path)
		if err != nil {
			return err
		}
		if _, pinned := seen[filepath.ToSlash(relative)]; !pinned {
			return fmt.Errorf("fixture %s is present on disk but not pinned by the freeze", relative)
		}
		return nil
	})
}

// workspace is one hermetic on-disk materialization of the frozen fixtures in
// the exact layout the broker's flags expect.
type workspace struct {
	root       string
	suiteDir   string
	scriptPath string
	scriptPin  string
	policyPins map[string]string
	catalogs   map[string]catalogInfo
	token      string
}

type catalogInfo struct {
	path   string
	sha256 string
}

// federationLane mirrors the broker's catalog schema exactly.
type federationLane struct {
	LaneID                      string `json:"lane_id"`
	RetrievalExecutable         string `json:"retrieval_executable"`
	RetrievalExecutableSHA256   string `json:"retrieval_executable_sha256"`
	RetrievalStore              string `json:"retrieval_store"`
	RetrievalState              string `json:"retrieval_state"`
	RetrievalEvidenceStore      string `json:"retrieval_evidence_store"`
	RetrievalAdmissionPolicy    string `json:"retrieval_admission_policy"`
	RetrievalAdmissionPolicySHA string `json:"retrieval_admission_policy_sha256"`
}

type federationCatalog struct {
	SchemaVersion string           `json:"schema_version"`
	RecordKind    string           `json:"record_kind"`
	Lanes         []federationLane `json:"lanes"`
}

func materializeWorkspace(suiteDir string, freeze *suiteFreeze) (*workspace, error) {
	tempRoot, err := os.MkdirTemp("", "mcp01-acceptance-")
	if err != nil {
		return nil, err
	}
	// The broker rejects symlink path components, so resolve the temp root once.
	root, err := filepath.EvalSymlinks(tempRoot)
	if err != nil {
		return nil, err
	}
	ws := &workspace{
		root: root, suiteDir: suiteDir,
		policyPins: make(map[string]string), catalogs: make(map[string]catalogInfo),
	}
	tokenDigest := sha256.Sum256([]byte(freeze.SuiteID + "/" + freeze.Revision))
	ws.token = hex.EncodeToString(tokenDigest[:])
	for _, directory := range []string{"repo", "bin", "policies", "registry", "catalogs", "http"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			return nil, err
		}
	}
	for _, lane := range []string{"solo", "alpha", "beta", "gamma"} {
		for _, leaf := range []string{"store", "state", "evidence"} {
			if err := os.MkdirAll(filepath.Join(root, "lanes", lane, leaf), 0o755); err != nil {
				return nil, err
			}
		}
	}
	ws.scriptPath = filepath.Join(root, "bin", "lane-child.sh")
	if err := ws.copyFixture("fixtures/lane-child.sh", ws.scriptPath, 0o555); err != nil {
		return nil, err
	}
	ws.scriptPin, _, err = hashFile(ws.scriptPath)
	if err != nil {
		return nil, err
	}
	for _, policy := range []string{
		"alpha", "beta", "deny-retrieval", "deny-deleted", "deny-tombstone", "deny-absent",
	} {
		target := filepath.Join(root, "policies", policy+".json")
		if err := ws.copyFixture("fixtures/policies/"+policy+".json", target, 0o444); err != nil {
			return nil, err
		}
		pin, _, err := hashFile(target)
		if err != nil {
			return nil, err
		}
		ws.policyPins[policy] = pin
	}
	registryTarget := filepath.Join(root, "registry", "candidate-manifest.json")
	if err := ws.copyFixture("fixtures/registry/candidate-manifest.json", registryTarget, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(root, "http", "token"), []byte(ws.token+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := ws.buildCatalog("fed-ok", []string{"alpha", "beta"}, map[string]string{"alpha": "alpha", "beta": "beta"}); err != nil {
		return nil, err
	}
	if err := ws.buildCatalog("fed-tamper", []string{"alpha", "beta"}, map[string]string{"alpha": "alpha", "beta": "beta"}); err != nil {
		return nil, err
	}
	for name, policy := range map[string]string{
		"fed-acl":           "deny-retrieval",
		"fed-del-deleted":   "deny-deleted",
		"fed-del-tombstone": "deny-tombstone",
		"fed-del-absent":    "deny-absent",
	} {
		if err := ws.buildCatalog(name, []string{"gamma"}, map[string]string{"gamma": policy}); err != nil {
			return nil, err
		}
	}
	return ws, nil
}

func (ws *workspace) copyFixture(relative, target string, mode os.FileMode) error {
	raw, err := os.ReadFile(filepath.Join(ws.suiteDir, filepath.FromSlash(relative)))
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, raw, mode); err != nil {
		return err
	}
	// An earlier run may have left a read-only file; enforce the exact mode.
	return os.Chmod(target, mode)
}

func (ws *workspace) buildCatalog(name string, laneIDs []string, policies map[string]string) error {
	catalog := federationCatalog{SchemaVersion: "1.0.0", RecordKind: "retrieval_federation_catalog"}
	for _, laneID := range laneIDs {
		policy := policies[laneID]
		catalog.Lanes = append(catalog.Lanes, federationLane{
			LaneID:                      laneID,
			RetrievalExecutable:         ws.scriptPath,
			RetrievalExecutableSHA256:   ws.scriptPin,
			RetrievalStore:              filepath.Join(ws.root, "lanes", laneID, "store"),
			RetrievalState:              filepath.Join(ws.root, "lanes", laneID, "state"),
			RetrievalEvidenceStore:      filepath.Join(ws.root, "lanes", laneID, "evidence"),
			RetrievalAdmissionPolicy:    filepath.Join(ws.root, "policies", policy+".json"),
			RetrievalAdmissionPolicySHA: ws.policyPins[policy],
		})
	}
	encoded, err := json.Marshal(catalog)
	if err != nil {
		return err
	}
	path := filepath.Join(ws.root, "catalogs", name+".json")
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o444); err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	ws.catalogs[name] = catalogInfo{path: path, sha256: hex.EncodeToString(digest[:])}
	return nil
}

// restoreCatalog rebuilds one derived catalog byte-identically from the
// frozen fixture pins after a deliberate tamper.
func (ws *workspace) restoreCatalog(name string) error {
	catalog, exists := ws.catalogs[name]
	if !exists {
		return fmt.Errorf("unknown catalog %q", name)
	}
	if err := os.Chmod(catalog.path, 0o644); err != nil {
		return err
	}
	previous := catalog.sha256
	switch name {
	case "fed-ok", "fed-tamper":
		if err := ws.buildCatalog(name, []string{"alpha", "beta"}, map[string]string{"alpha": "alpha", "beta": "beta"}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("catalog %q has no restore recipe", name)
	}
	if ws.catalogs[name].sha256 != previous {
		return fmt.Errorf("restored catalog %q is not byte-identical to its pinned build", name)
	}
	return nil
}

// installResponse places one frozen response fixture as a lane's next
// signed-current reply.
func (ws *workspace) installResponse(lane, responseFixture string) error {
	return ws.copyFixture("fixtures/responses/"+responseFixture, filepath.Join(ws.root, "lanes", lane, "store", "response.json"), 0o644)
}

func (ws *workspace) setBlock(lane string, blocked bool) error {
	marker := filepath.Join(ws.root, "lanes", lane, "store", "block")
	if blocked {
		return os.WriteFile(marker, []byte("block\n"), 0o644)
	}
	err := os.Remove(marker)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// tamperFile flips one content byte in place, preserving length and mode.
func tamperFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return errors.New("cannot tamper an empty file")
	}
	raw[len(raw)-2] ^= 0x01
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return err
	}
	return os.Chmod(path, info.Mode())
}

// restoreFixtureFile rewrites a workspace file from its frozen fixture bytes.
func (ws *workspace) restoreFixtureFile(relative, target string, mode os.FileMode) error {
	if err := os.Chmod(target, 0o644); err != nil {
		return err
	}
	return ws.copyFixture(relative, target, mode)
}

func (ws *workspace) soloArguments() []string {
	return []string{
		"--repository-root", filepath.Join(ws.root, "repo"),
		"--registry", filepath.Join(ws.root, "registry", "candidate-manifest.json"),
		"--retrieval-executable", ws.scriptPath,
		"--retrieval-executable-sha256", ws.scriptPin,
		"--retrieval-store", filepath.Join(ws.root, "lanes", "solo", "store"),
		"--retrieval-state", filepath.Join(ws.root, "lanes", "solo", "state"),
		"--retrieval-evidence-store", filepath.Join(ws.root, "lanes", "solo", "evidence"),
		"--retrieval-admission-policy", filepath.Join(ws.root, "policies", "alpha.json"),
		"--retrieval-admission-policy-sha256", ws.policyPins["alpha"],
	}
}

func (ws *workspace) federationArguments(catalogName string) []string {
	catalog := ws.catalogs[catalogName]
	return []string{
		"--repository-root", filepath.Join(ws.root, "repo"),
		"--retrieval-catalog", catalog.path,
		"--retrieval-catalog-sha256", catalog.sha256,
	}
}

func (ws *workspace) httpArguments(bind string) []string {
	return append(ws.soloArguments(),
		"--http-bind", bind,
		"--http-token-file", filepath.Join(ws.root, "http", "token"),
	)
}

func (ws *workspace) remove() {
	_ = os.Chmod(ws.scriptPath, 0o755)
	for _, catalog := range ws.catalogs {
		_ = os.Chmod(catalog.path, 0o644)
	}
	if entries, err := os.ReadDir(filepath.Join(ws.root, "policies")); err == nil {
		for _, entry := range entries {
			_ = os.Chmod(filepath.Join(ws.root, "policies", entry.Name()), 0o644)
		}
	}
	_ = os.RemoveAll(ws.root)
}

// assertNoDisclosure fails when a serialized transcript leaks identifiers that
// authorization or deletion must withhold before metadata disclosure.
func assertNoDisclosure(serialized []byte, forbidden ...string) error {
	for _, marker := range forbidden {
		if strings.Contains(string(serialized), marker) {
			return fmt.Errorf("fail-closed result disclosed %q", marker)
		}
	}
	return nil
}
