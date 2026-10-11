package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const (
	multidomainFixtureRoot = "testdata/scorer-blind-multidomain-v2"
	multidomainFreezePath  = multidomainFixtureRoot + "/materialized/evaluation-freezes/sha256/dd/ddb38ed65dce0a56e6308689b82c085bd1276e3e1f6d48dea68dc792d5d0959d.json"
	multidomainCorePath    = multidomainFixtureRoot + "/binding-requirements.core.json"
)

func TestMultidomainBindingRequirementsMaterializeDeterministicallyWithoutAuthority(t *testing.T) {
	freezeBefore, err := os.ReadFile(multidomainFreezePath)
	if err != nil {
		t.Fatal(err)
	}
	first, firstPath, err := MaterializeMultidomainBindingRequirements(
		multidomainCorePath, multidomainFreezePath, p1MultidomainFreezeDocumentSHA256,
		multidomainFixtureRoot, t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, err := MaterializeMultidomainBindingRequirements(
		multidomainCorePath, multidomainFreezePath, p1MultidomainFreezeDocumentSHA256,
		multidomainFixtureRoot, t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("independent binding-requirements materializations differ")
	}
	if first.ManifestID != "retrieval-binding-requirements:sha256:8c58e1e9cfe2cef672f104cfc88ab0229ba666e829d94188cda277b6a4e87f49" || second.ManifestID != first.ManifestID {
		t.Fatalf("unexpected requirements identity %s / %s", first.ManifestID, second.ManifestID)
	}
	if digestBytes(firstBytes) != "sha256:96b1203a5553898ddafcf57c5e88bdf512f6d88af598302ae35b697e6ec537da" {
		t.Fatalf("unexpected requirements document digest %s", digestBytes(firstBytes))
	}
	if first.Ready || first.ExecutionAuthorized || first.VerifiedArtifactCount != 0 || first.GapCount != 38 || first.GapCount != len(first.Gaps) {
		t.Fatalf("requirements manifest escaped its blocked boundary: %+v", first)
	}
	freezeAfter, err := os.ReadFile(multidomainFreezePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(freezeBefore, freezeAfter) || digestBytes(freezeAfter) != p1MultidomainFreezeDocumentSHA256 {
		t.Fatal("requirements materialization changed the immutable freeze bytes")
	}
}

func TestMultidomainBindingRequirementsKeepThreeIndependentAuthoritiesAndTypedGaps(t *testing.T) {
	manifest, _, err := MaterializeMultidomainBindingRequirements(
		multidomainCorePath, multidomainFreezePath, p1MultidomainFreezeDocumentSHA256,
		multidomainFixtureRoot, t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	wantVersions := map[string]string{"cilium": "v1.19.5", "go": "go1.26.5", "kubernetes": "v1.36.2"}
	policyScopes := make(map[string]struct{})
	for _, authority := range manifest.SourceAuthorities {
		if wantVersions[authority.ComponentID] != authority.ComponentVersion {
			t.Fatalf("unexpected source authority %+v", authority)
		}
		if _, exists := policyScopes[authority.AdmissionPolicyScopeID]; exists {
			t.Fatalf("aliased admission-policy scope %s", authority.AdmissionPolicyScopeID)
		}
		policyScopes[authority.AdmissionPolicyScopeID] = struct{}{}
	}
	if len(manifest.SourceAuthorities) != 3 || len(policyScopes) != 3 {
		t.Fatalf("source authority denominator collapsed: %+v", manifest.SourceAuthorities)
	}
	required := make(map[string]struct{}, len(manifest.RequiredExactBindings))
	for _, field := range manifest.RequiredExactBindings {
		required[field] = struct{}{}
	}
	for _, field := range []string{
		"snapshot_manifest_id", "snapshot_manifest_document_sha256",
		"evidence_manifest_id", "evidence_manifest_document_sha256",
		"lexical_index_id", "lexical_index_document_sha256",
	} {
		if _, exists := required[field]; !exists {
			t.Fatalf("new exact binding %s is absent", field)
		}
	}
	scopes := make(map[string]int)
	prefixes := make(map[string]string)
	for _, gap := range manifest.Gaps {
		if gap.Code != "required_artifact_absent" || !gap.Blocking || len(gap.AuthorityIDs) == 0 || len(gap.RequiredFields) == 0 {
			t.Fatalf("untyped or nonblocking gap %+v", gap)
		}
		if gap.Scope == "source_authority" && !gap.DistinctAcrossAuthorities {
			t.Fatalf("authority-local artifact may alias another authority: %+v", gap)
		}
		scopes[gap.Scope]++
		prefixes[gap.ArtifactKind] = gap.RequiredIDPrefix
	}
	if scopes["source_authority"] != 9 || scopes["shared_corpus"] != 5 || scopes["comparison"] != 2 || scopes["evaluation_case"] != 22 {
		t.Fatalf("unexpected typed gap denominator: %+v", scopes)
	}
	for kind, prefix := range map[string]string{
		"snapshot_manifest": "snapshot-manifest:",
		"evidence_manifest": "evidence-manifest:",
		"lexical_index":     "lexical-index:",
	} {
		if prefixes[kind] != prefix {
			t.Fatalf("%s gap lost its typed ID prefix: %q", kind, prefixes[kind])
		}
	}
}

func TestMultidomainBindingRequirementsRejectCollapseAliasingDriftAndReadiness(t *testing.T) {
	core := loadMultidomainBindingRequirementsCore(t)
	freeze := loadMultidomainFreeze(t)
	tests := []struct {
		name   string
		mutate func(*MultidomainBindingRequirementsCore)
	}{
		{name: "singular source collapse", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.SourceAuthorities = value.SourceAuthorities[:1]
		}},
		{name: "aliased admission policies", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.SourceAuthorities[1].AdmissionPolicyScopeID = value.SourceAuthorities[0].AdmissionPolicyScopeID
		}},
		{name: "mixed source lineage", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.SourceAuthorities[2].SourceCommitSHA = value.SourceAuthorities[0].SourceCommitSHA
		}},
		{name: "backdated requirements", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.RequirementsFrozenAt = freeze.FrozenAt
		}},
		{name: "backdated policy allowance", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.SourceAuthorities[0].PolicyEvaluatedAtNotBefore = "2026-07-20T11:59:59Z"
		}},
		{name: "expired policy allowance", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.SourceAuthorities[0].PolicyMustRemainFreshStrictlyAfter = "2026-07-20T11:59:59Z"
		}},
		{name: "partial exact ID hash pair", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.RequiredExactBindings = removeString(value.RequiredExactBindings, "snapshot_manifest_document_sha256")
		}},
		{name: "missing shared lineage authority", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.RequiredSharedLineageAuthorities = value.RequiredSharedLineageAuthorities[:2]
		}},
		{name: "premature ready state", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.Ready = true
		}},
		{name: "premature evaluation authority", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.Capabilities.EvaluationAuthorized = true
		}},
		{name: "workflows authority shortcut", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.AuthorityRules.WorkflowsLaneAuthorityReuseForbidden = false
		}},
		{name: "unaccepted scorer shortcut", mutate: func(value *MultidomainBindingRequirementsCore) {
			value.AuthorityRules.UnacceptedScorerAuthorityForbidden = false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := core
			changed.RequiredExactBindings = append([]string(nil), core.RequiredExactBindings...)
			changed.RequiredSharedLineageAuthorities = append([]string(nil), core.RequiredSharedLineageAuthorities...)
			changed.SourceAuthorities = cloneMultidomainSourceAuthorities(core.SourceAuthorities)
			test.mutate(&changed)
			if _, err := sealMultidomainBindingRequirements(changed, freeze, p1MultidomainFreezeDocumentSHA256, multidomainFixtureRoot); err == nil {
				t.Fatal("unsafe binding requirements mutation was accepted")
			}
		})
	}
}

func TestMultidomainBindingRequirementsRejectFreezeDriftAndCallerMismatch(t *testing.T) {
	core := loadMultidomainBindingRequirementsCore(t)
	freeze := loadMultidomainFreeze(t)
	freeze.Cases[0].Query += " changed"
	if _, err := sealMultidomainBindingRequirements(core, freeze, p1MultidomainFreezeDocumentSHA256, multidomainFixtureRoot); err == nil {
		t.Fatal("changed frozen question was accepted")
	}
	if _, _, err := MaterializeMultidomainBindingRequirements(
		multidomainCorePath, multidomainFreezePath, "sha256:"+string(bytes.Repeat([]byte{'0'}, 64)),
		multidomainFixtureRoot, t.TempDir(),
	); err == nil {
		t.Fatal("wrong freeze caller pin was accepted")
	}
}

func TestMultidomainBindingRequirementsRejectSourceStoreOverlap(t *testing.T) {
	freezeBefore, err := os.ReadFile(multidomainFreezePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := MaterializeMultidomainBindingRequirements(
		multidomainCorePath, multidomainFreezePath, p1MultidomainFreezeDocumentSHA256,
		multidomainFixtureRoot, multidomainFixtureRoot,
	); err == nil {
		t.Fatal("overlapping source and output roots were accepted")
	}
	freezeAfter, err := os.ReadFile(multidomainFreezePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(freezeBefore, freezeAfter) {
		t.Fatal("overlap rejection changed an immutable input")
	}
}

func loadMultidomainBindingRequirementsCore(t *testing.T) MultidomainBindingRequirementsCore {
	t.Helper()
	data, err := os.ReadFile(multidomainCorePath)
	if err != nil {
		t.Fatal(err)
	}
	var core MultidomainBindingRequirementsCore
	if err := decodeStrictCanonical(data, &core); err != nil {
		t.Fatal(err)
	}
	return core
}

func loadMultidomainFreeze(t *testing.T) ScorerBlindEvaluationFreeze {
	t.Helper()
	data, err := os.ReadFile(multidomainFreezePath)
	if err != nil {
		t.Fatal(err)
	}
	var freeze ScorerBlindEvaluationFreeze
	if err := decodeStrictCanonical(data, &freeze); err != nil {
		t.Fatal(err)
	}
	return freeze
}

func cloneMultidomainSourceAuthorities(values []MultidomainSourceAuthorityRequirement) []MultidomainSourceAuthorityRequirement {
	result := append([]MultidomainSourceAuthorityRequirement(nil), values...)
	for index := range result {
		result[index].SourceKeys = append([]string(nil), values[index].SourceKeys...)
	}
	return result
}

func removeString(values []string, target string) []string {
	result := make([]string, 0, len(values)-1)
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}

func TestMultidomainBindingRequirementsCoreIsStrictCanonical(t *testing.T) {
	data, err := os.ReadFile(filepath.Clean(multidomainCorePath))
	if err != nil {
		t.Fatal(err)
	}
	var core MultidomainBindingRequirementsCore
	if err := decodeStrictCanonical(data, &core); err != nil {
		t.Fatal(err)
	}
}
