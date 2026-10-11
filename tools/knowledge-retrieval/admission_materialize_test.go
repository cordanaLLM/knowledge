package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeAdmissionPolicyDerivesCanonicalImmutableIdentity(t *testing.T) {
	core := materializationTestPolicyCore()
	corePath := materializationWriteCanonical(t, filepath.Join(t.TempDir(), "admission-policy-core.json"), core)
	store := filepath.Join(t.TempDir(), "retrieval-store")

	first, firstPath, err := MaterializeAdmissionPolicy(corePath, store)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, err := MaterializeAdmissionPolicy(corePath, store)
	if err != nil {
		t.Fatal(err)
	}
	compactCore, err := json.Marshal(core)
	if err != nil {
		t.Fatal(err)
	}
	wantPayloadDigest := digestBytes(compactCore)
	if first.PolicyPayloadSHA256 != wantPayloadDigest || first.PolicyID != "retrieval-admission:"+wantPayloadDigest {
		t.Fatalf("materialized identity = %q, %q; want payload %q", first.PolicyID, first.PolicyPayloadSHA256, wantPayloadDigest)
	}
	if first != second || firstPath != secondPath {
		t.Fatalf("repeat materialization is unstable: first=%+v %q second=%+v %q", first, firstPath, second, secondPath)
	}
	hexDigest := strings.TrimPrefix(wantPayloadDigest, "sha256:")
	wantPath := filepath.Join(store, "admission-policies", "sha256", hexDigest[:2], hexDigest+".json")
	if firstPath != wantPath {
		t.Fatalf("materialized path = %q; want %q", firstPath, wantPath)
	}

	stored, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AdmissionPolicy
	if err := decodeStrictCanonical(stored, &decoded); err != nil {
		t.Fatalf("stored policy is not strict canonical JSON: %v", err)
	}
	wantStored, err := marshalDocument(first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, wantStored) || decoded != first {
		t.Fatal("stored policy differs from its canonical materialized value")
	}
	if info, err := os.Stat(firstPath); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("materialized mode = %v, %v; want 0444", info, err)
	}
}

func TestMaterializeAdmissionPolicyRejectsNonCanonicalOrUnknownCore(t *testing.T) {
	core := materializationTestPolicyCore()
	canonical, err := marshalDocument(core)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{name: "compact serialization", data: bytes.TrimSpace(canonical)},
		{name: "trailing whitespace", data: append(append([]byte(nil), canonical...), '\n')},
		{name: "unknown field", data: bytes.Replace(canonical, []byte("\n}"), []byte(",\n  \"caller_policy_id\": \"retrieval-admission:sha256:deadbeef\"\n}"), 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			corePath := filepath.Join(t.TempDir(), "core.json")
			if err := os.WriteFile(corePath, test.data, 0o644); err != nil {
				t.Fatal(err)
			}
			store := filepath.Join(t.TempDir(), "store")
			if _, _, err := MaterializeAdmissionPolicy(corePath, store); err == nil {
				t.Fatal("MaterializeAdmissionPolicy() accepted a non-strict core")
			}
			if countAllFiles(store) != 0 {
				t.Fatal("invalid core produced a CAS object")
			}
		})
	}
}

func TestMaterializeAdmissionPolicyRejectsInvalidContractBeforeCommit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AdmissionPolicyCore)
	}{
		{name: "schema", mutate: func(core *AdmissionPolicyCore) { core.SchemaVersion = "2.0.0" }},
		{name: "kind", mutate: func(core *AdmissionPolicyCore) { core.PolicyKind = "private_retrieval_admission" }},
		{name: "state", mutate: func(core *AdmissionPolicyCore) { core.State = "draft" }},
		{name: "snapshot manifest", mutate: func(core *AdmissionPolicyCore) { core.SnapshotManifestID = "snapshot-manifest:not-a-digest" }},
		{name: "evidence manifest", mutate: func(core *AdmissionPolicyCore) { core.EvidenceManifestID = "evidence-manifest:not-a-digest" }},
		{name: "lineage", mutate: func(core *AdmissionPolicyCore) { core.SourceID = " source:test" }},
		{name: "scope", mutate: func(core *AdmissionPolicyCore) { core.AccessScope = "private" }},
		{name: "retrieval", mutate: func(core *AdmissionPolicyCore) { core.RetrievalAllowed = false }},
		{name: "source state", mutate: func(core *AdmissionPolicyCore) { core.SourceState = "empty" }},
		{name: "deletion state", mutate: func(core *AdmissionPolicyCore) { core.DeletionState = "deleted" }},
		{name: "tombstone", mutate: func(core *AdmissionPolicyCore) { core.Tombstone = true }},
		{name: "evaluated time", mutate: func(core *AdmissionPolicyCore) { core.EvaluatedAt = "2026-07-16T02:00:00+02:00" }},
		{name: "fresh time", mutate: func(core *AdmissionPolicyCore) { core.FreshUntil = "tomorrow" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := materializationTestPolicyCore()
			test.mutate(&core)
			corePath := materializationWriteCanonical(t, filepath.Join(t.TempDir(), "core.json"), core)
			store := filepath.Join(t.TempDir(), "store")
			if _, _, err := MaterializeAdmissionPolicy(corePath, store); err == nil {
				t.Fatal("MaterializeAdmissionPolicy() accepted an invalid admission contract")
			}
			if countAllFiles(store) != 0 {
				t.Fatal("invalid admission contract produced a CAS object")
			}
		})
	}
}

func TestMaterializeAdmissionPolicyFailsClosedOnCASCollision(t *testing.T) {
	core := materializationTestPolicyCore()
	corePath := materializationWriteCanonical(t, filepath.Join(t.TempDir(), "core.json"), core)
	policy, err := deriveAdmissionPolicy(core)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := contentObjectPath("admission-policies", policy.PolicyPayloadSHA256)
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(t.TempDir(), "store")
	target := filepath.Join(store, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("collision\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, _, err := MaterializeAdmissionPolicy(corePath, store); err == nil {
		t.Fatal("MaterializeAdmissionPolicy() accepted a different object at the immutable path")
	}
	stored, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != "collision\n" {
		t.Fatal("CAS collision modified the pre-existing immutable object")
	}
}

func materializationTestPolicyCore() AdmissionPolicyCore {
	return AdmissionPolicyCore{
		SchemaVersion:      retrievalSchemaVersion,
		PolicyKind:         "public_retrieval_admission",
		State:              "active",
		SnapshotManifestID: "snapshot-manifest:sha256:" + strings.Repeat("a", 64),
		EvidenceManifestID: "evidence-manifest:sha256:" + strings.Repeat("b", 64),
		SnapshotID:         "snp:test:1",
		SourceID:           "src:github:argoproj/argo-cd",
		ComponentID:        "cmp:github:argoproj/argo-cd",
		ComponentVersionID: "cv:argocd:v3.4.5",
		AccessScope:        "public",
		RetrievalAllowed:   true,
		SourceState:        "present",
		DeletionState:      "active",
		Tombstone:          false,
		EvaluatedAt:        "2026-07-16T00:00:00Z",
		FreshUntil:         "2026-07-17T00:00:00Z",
	}
}

func materializationWriteCanonical(t *testing.T, target string, value any) string {
	t.Helper()
	data, err := marshalDocument(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return target
}
