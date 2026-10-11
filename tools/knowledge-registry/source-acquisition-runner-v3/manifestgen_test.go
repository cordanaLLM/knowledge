package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestGenerateExecutionManifest regenerates execution-manifest.json from the
// current invariant runner source bytes. It is a build-time generator, not an
// assertion: it only runs when GEN_MANIFEST=1 so ordinary `go test` never
// rewrites the committed manifest. Run once after any source edit:
//
//	GEN_MANIFEST=1 go test -run TestGenerateExecutionManifest
func TestGenerateExecutionManifest(t *testing.T) {
	if os.Getenv("GEN_MANIFEST") != "1" {
		t.Skip("set GEN_MANIFEST=1 to regenerate execution-manifest.json")
	}
	artifacts := make([]executionArtifact, 0, len(expectedExecutionArtifacts))
	for logicalPath, role := range expectedExecutionArtifacts {
		local := filepath.Base(logicalPath)
		raw, err := os.ReadFile(local)
		if err != nil {
			t.Fatalf("read artifact %s: %v", local, err)
		}
		artifacts = append(artifacts, executionArtifact{
			LogicalPath: logicalPath,
			Role:        role,
			SHA256:      sha256String(raw),
			Bytes:       int64(len(raw)),
		})
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].LogicalPath < artifacts[j].LogicalPath })
	core := executionManifestCore{
		Schema:            "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-execution-manifest-v1.schema.json",
		SchemaVersion:     "1.0.0",
		Canonicalization:  canonicalProfile,
		ManifestKind:      "source_acquisition_runner_v3_execution_byte_manifest",
		AuthorityState:    "non_authoritative",
		VerificationState: "expected_bytes_unverified",
		ExecutionEligible: false,
		Toolchain: executionToolchain{
			GoVersion: "go1.26.5-X:nodwarf5", GOOS: "linux", GOARCH: "amd64", GOAMD64: "v1",
			BinaryPath: "/usr/lib/go/bin/go", BinarySHA256: "sha256:24ede1c93e3882e0b105ff45228e7258d36a4ab3ebabf39580e28668de683696",
		},
		Dependencies: executionDependencyClosure{
			ModuleMode: "go_mod_no_external_modules", ExternalModules: []string{}, StandardLibrary: "go1.26.5-X:nodwarf5",
			GOROOTPath: "/usr/lib/go", GOROOTTreeFormat: "type-nul-path-nul-mode-nul-size-nul-content-nul-v1",
			GOROOTTreeSHA256:  "sha256:843de40ce8db6950451b47ebcf080317e400be1be18a99ef23c4b5512117db8b",
			GOROOTTreeEntries: 16671, GOROOTLogicalBytes: 225627376,
		},
		Artifacts: artifacts,
	}
	_, raw, err := materializeExecutionManifest(core)
	if err != nil {
		t.Fatalf("materialize execution manifest: %v", err)
	}
	if err := os.WriteFile("execution-manifest.json", raw, 0o644); err != nil {
		t.Fatalf("write execution manifest: %v", err)
	}
}
