package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const maxExecutionManifestBytes = 128 * 1024

//go:embed execution-manifest.json
var embeddedExecutionManifest []byte

type executionGate struct {
	ManifestID                   string `json:"manifest_id"`
	ManifestPayloadSHA256        string `json:"manifest_payload_sha256"`
	VerificationState            string `json:"verification_state"`
	ExternalVerificationRequired bool   `json:"external_verification_required"`
	Verified                     bool   `json:"verified"`
	PredecessorEligible          bool   `json:"predecessor_eligible"`
}

type executionToolchain struct {
	GoVersion    string `json:"go_version"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	GOAMD64      string `json:"goamd64"`
	BinaryPath   string `json:"binary_path"`
	BinarySHA256 string `json:"binary_sha256"`
}

type executionDependencyClosure struct {
	ModuleMode         string   `json:"module_mode"`
	ExternalModules    []string `json:"external_modules"`
	StandardLibrary    string   `json:"standard_library"`
	GOROOTPath         string   `json:"goroot_path"`
	GOROOTTreeFormat   string   `json:"goroot_tree_format"`
	GOROOTTreeSHA256   string   `json:"goroot_tree_sha256"`
	GOROOTTreeEntries  int64    `json:"goroot_tree_entries"`
	GOROOTLogicalBytes int64    `json:"goroot_logical_bytes"`
}

type executionArtifact struct {
	LogicalPath string `json:"logical_path"`
	Role        string `json:"role"`
	SHA256      string `json:"sha256"`
	Bytes       int64  `json:"bytes"`
}

type executionManifestCore struct {
	Schema            string                     `json:"$schema"`
	SchemaVersion     string                     `json:"schema_version"`
	Canonicalization  string                     `json:"canonicalization"`
	ManifestKind      string                     `json:"manifest_kind"`
	AuthorityState    string                     `json:"authority_state"`
	VerificationState string                     `json:"verification_state"`
	ExecutionEligible bool                       `json:"execution_eligible"`
	Toolchain         executionToolchain         `json:"toolchain"`
	Dependencies      executionDependencyClosure `json:"dependencies"`
	Artifacts         []executionArtifact        `json:"artifacts"`
}

type executionManifest struct {
	ManifestID            string `json:"manifest_id"`
	ManifestPayloadSHA256 string `json:"manifest_payload_sha256"`
	executionManifestCore
}

// expectedExecutionArtifacts binds ONLY the invariant runner source bytes plus
// the module definition. Unlike the P1-SRC-03 manifest it carries no
// contract-specific artifacts, so one execution manifest covers every authority
// the generalized runner can be pointed at.
var expectedExecutionArtifacts = map[string]string{
	"tools/knowledge-registry/source-acquisition-runner-v3/contract.go":           "runner_source",
	"tools/knowledge-registry/source-acquisition-runner-v3/execution_manifest.go": "runner_source",
	"tools/knowledge-registry/source-acquisition-runner-v3/go.mod":                "module_definition",
	"tools/knowledge-registry/source-acquisition-runner-v3/main.go":               "runner_source",
	"tools/knowledge-registry/source-acquisition-runner-v3/plan.go":               "runner_source",
	"tools/knowledge-registry/source-acquisition-runner-v3/runner.go":             "runner_source",
	"tools/knowledge-registry/source-acquisition-runner-v3/store.go":              "runner_source",
}

func exactExecutionManifest() (executionManifest, error) {
	if len(embeddedExecutionManifest) == 0 || len(embeddedExecutionManifest) > maxExecutionManifestBytes {
		return executionManifest{}, errors.New("embedded execution manifest is empty or over-bound")
	}
	if _, err := parseStrictJSON(embeddedExecutionManifest); err != nil {
		return executionManifest{}, fmt.Errorf("strict embedded execution manifest JSON: %w", err)
	}
	var value executionManifest
	if err := json.Unmarshal(embeddedExecutionManifest, &value); err != nil {
		return executionManifest{}, err
	}
	if err := validateExecutionManifestCore(value.executionManifestCore); err != nil {
		return executionManifest{}, err
	}
	rebuilt, raw, err := materializeExecutionManifest(value.executionManifestCore)
	if err != nil {
		return executionManifest{}, err
	}
	if value.ManifestID != rebuilt.ManifestID || value.ManifestPayloadSHA256 != rebuilt.ManifestPayloadSHA256 || !bytes.Equal(embeddedExecutionManifest, raw) {
		return executionManifest{}, errors.New("embedded execution manifest content address or exact bytes are invalid")
	}
	return value, nil
}

func exactExecutionGateBinding() (executionGate, error) {
	manifest, err := exactExecutionManifest()
	if err != nil {
		return executionGate{}, err
	}
	return executionGate{
		ManifestID: manifest.ManifestID, ManifestPayloadSHA256: manifest.ManifestPayloadSHA256,
		VerificationState: "external_exact_byte_verification_required", ExternalVerificationRequired: true,
		Verified: false, PredecessorEligible: false,
	}, nil
}

func materializeExecutionManifest(core executionManifestCore) (executionManifest, []byte, error) {
	if err := validateExecutionManifestCore(core); err != nil {
		return executionManifest{}, nil, err
	}
	payload, err := canonicalJSON(core)
	if err != nil {
		return executionManifest{}, nil, err
	}
	payloadSHA := sha256String(payload)
	value := executionManifest{ManifestID: "source-acquisition-execution-manifest:" + payloadSHA, ManifestPayloadSHA256: payloadSHA, executionManifestCore: core}
	raw, err := documentJSON(value)
	return value, raw, err
}

func validateExecutionManifestCore(core executionManifestCore) error {
	if core.Schema != "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-execution-manifest-v1.schema.json" || core.SchemaVersion != "1.0.0" || core.Canonicalization != canonicalProfile || core.ManifestKind != "source_acquisition_runner_v3_execution_byte_manifest" {
		return errors.New("execution manifest schema or kind is invalid")
	}
	if core.AuthorityState != "non_authoritative" || core.VerificationState != "expected_bytes_unverified" || core.ExecutionEligible {
		return errors.New("execution manifest authority or verification state widened")
	}
	wantToolchain := executionToolchain{GoVersion: "go1.26.5-X:nodwarf5", GOOS: "linux", GOARCH: "amd64", GOAMD64: "v1", BinaryPath: "/usr/lib/go/bin/go", BinarySHA256: "sha256:24ede1c93e3882e0b105ff45228e7258d36a4ab3ebabf39580e28668de683696"}
	if core.Toolchain != wantToolchain {
		return errors.New("execution manifest toolchain binding differs from the exact tuple")
	}
	if core.Dependencies.ModuleMode != "go_mod_no_external_modules" || len(core.Dependencies.ExternalModules) != 0 || core.Dependencies.StandardLibrary != core.Toolchain.GoVersion || core.Dependencies.GOROOTPath != "/usr/lib/go" || core.Dependencies.GOROOTTreeFormat != "type-nul-path-nul-mode-nul-size-nul-content-nul-v1" || core.Dependencies.GOROOTTreeSHA256 != "sha256:843de40ce8db6950451b47ebcf080317e400be1be18a99ef23c4b5512117db8b" || core.Dependencies.GOROOTTreeEntries != 16671 || core.Dependencies.GOROOTLogicalBytes != 225627376 {
		return errors.New("execution manifest dependency closure is not exact")
	}
	if len(core.Artifacts) != len(expectedExecutionArtifacts) {
		return errors.New("execution manifest artifact denominator changed")
	}
	seen := make(map[string]struct{}, len(core.Artifacts))
	paths := make([]string, 0, len(core.Artifacts))
	for _, artifact := range core.Artifacts {
		if artifact.LogicalPath == "" || !utf8.ValidString(artifact.LogicalPath) || filepath.IsAbs(artifact.LogicalPath) || filepath.ToSlash(filepath.Clean(artifact.LogicalPath)) != artifact.LogicalPath || strings.HasPrefix(artifact.LogicalPath, "../") || artifact.Bytes < 0 || !validSHA256(artifact.SHA256) {
			return errors.New("execution manifest contains an unsafe artifact binding")
		}
		role, ok := expectedExecutionArtifacts[artifact.LogicalPath]
		if !ok || artifact.Role != role {
			return errors.New("execution manifest artifact path or role is outside the exact denominator")
		}
		if _, ok := seen[artifact.LogicalPath]; ok {
			return errors.New("execution manifest duplicates an artifact")
		}
		seen[artifact.LogicalPath] = struct{}{}
		paths = append(paths, artifact.LogicalPath)
	}
	if !sort.StringsAreSorted(paths) {
		return errors.New("execution manifest artifacts are not canonically ordered")
	}
	return nil
}

func sha256String(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
