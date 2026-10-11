package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	rerankerDefinitionFixture         = "testdata/evaluation-definitions/argocd-cpu-reranker-v1.core.json"
	pairedFusionDefinitionFixture     = "testdata/evaluation-definitions/argo-workflows-v4.0.7-lane-champion-fusion-v1.core.json"
	legacyFederationDefinitionFixture = "testdata/evaluation-definitions/argo-workflows-rollouts-federation-v1.core.json"
	federationV2DefinitionFixture     = "testdata/evaluation-definitions/argo-workflows-rollouts-federation-v2.core.json"
	federationDefinitionFixture       = "testdata/evaluation-definitions/argo-workflows-rollouts-federation-v3.core.json"
)

func TestFrozenExpandedEvaluationDefinitions(t *testing.T) {
	tests := []struct {
		name             string
		fixture          string
		wantID           string
		wantDocumentHash string
		wantMode         string
		wantExecution    string
		wantCases        int
		wantLanes        int
	}{
		{
			name:             "paired CPU reranker",
			fixture:          rerankerDefinitionFixture,
			wantID:           "retrieval-evaluation-definition:sha256:36eefbecfe78d204e11f70e0a45e82774074cca30a01b600a99cc82b35554766",
			wantDocumentHash: "sha256:791fcd79b1f602e278e180062ef172991542e0f0b88b3c5010b0b32d7b3b2129",
			wantMode:         "paired_reranker",
			wantExecution:    "blocked_exact_bindings",
			wantCases:        5,
			wantLanes:        1,
		},
		{
			name:             "paired Workflows lane-champion fusion",
			fixture:          pairedFusionDefinitionFixture,
			wantID:           "retrieval-evaluation-definition:sha256:78fd9a40493de286977d1d32a8c123bd0106ae139fb917589fdb50fcefe9d0cd",
			wantDocumentHash: "sha256:9bf87504e2e64c93e981b2d3d142abe6d9dca41799560933a43ddc9e372e30f9",
			wantMode:         "paired_fusion",
			wantExecution:    "blocked_exact_bindings",
			wantCases:        5,
			wantLanes:        1,
		},
		{
			name:             "legacy blocked Workflows and Rollouts federation",
			fixture:          legacyFederationDefinitionFixture,
			wantID:           "retrieval-evaluation-definition:sha256:b99d8a07791e60e017f20eb09be99acd7137c12bad6cedcbde010f8fb557df64",
			wantDocumentHash: "sha256:68cc764d10327f4596d4901fe0466fe1716580a476e44bf4311ebe018a0f08a3",
			wantMode:         "federated_lanes",
			wantExecution:    "blocked_exact_bindings",
			wantCases:        13,
			wantLanes:        2,
		},
		{
			name:             "lane-bound Workflows and Rollouts federation v2",
			fixture:          federationV2DefinitionFixture,
			wantID:           "retrieval-evaluation-definition:sha256:25ed2c6ccd962d8bbc3fcc37544a8f460dfb1e0168ae68f90e4571e8dde0ad73",
			wantDocumentHash: "sha256:184c089cdb06c668ea9cdd71317ad090b89270ea3568564667159644680da3e3",
			wantMode:         "federated_lanes",
			wantExecution:    "blocked_exact_bindings",
			wantCases:        13,
			wantLanes:        2,
		},
		{
			name:             "independently bound Workflows and Rollouts federation v3",
			fixture:          federationDefinitionFixture,
			wantID:           "retrieval-evaluation-definition:sha256:d40eb115226b6aa0b5ae7b40629ae820f04570d11ef561231187649a5cca8ddc",
			wantDocumentHash: "sha256:8fbde223103c32c69b873bf6abfa8e5884212607bf5b96cc52fb146116dd0566",
			wantMode:         "federated_lanes",
			wantExecution:    "blocked_exact_bindings",
			wantCases:        13,
			wantLanes:        2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := readExpandedEvaluationDefinitionCore(t, test.fixture)
			definition, err := sealExpandedEvaluationDefinition(core)
			if err != nil {
				t.Fatal(err)
			}
			if definition.DefinitionID != test.wantID || definition.ComparisonMode != test.wantMode || definition.ExecutionState != test.wantExecution || len(definition.Cases) != test.wantCases || len(definition.Inputs.Lanes) != test.wantLanes {
				t.Fatalf("frozen definition drifted: %+v", definition)
			}
			data, err := marshalDocument(definition)
			if err != nil {
				t.Fatal(err)
			}
			if digestBytes(data) != test.wantDocumentHash {
				t.Fatalf("frozen definition document hash changed: got %s want %s", digestBytes(data), test.wantDocumentHash)
			}
		})
	}
}

func TestExpandedEvaluationDefinitionsBindExactInputsAndAuthority(t *testing.T) {
	reranker := readExpandedEvaluationDefinitionCore(t, rerankerDefinitionFixture)
	if !reranker.Inputs.SameEvidenceGeneration || reranker.Inputs.CrossGenerationScoreComparison || reranker.Inputs.Lanes[0].Objects.BindingState != evaluationObjectBindingExact {
		t.Fatal("paired definition lost same-generation exact input isolation")
	}
	challenger := reranker.Profiles[0]
	if challenger.Role != "challenger" || challenger.Scorer.BindingState != evaluationObjectBindingExact || challenger.Scorer.ScorerRevision == nil || *challenger.Scorer.ScorerRevision != evaluatorRevision || challenger.Scorer.ScorerArtifactSHA256 == nil || *challenger.Scorer.ScorerArtifactSHA256 != "sha256:745bc32c9bffaee1c7b2bd0f25e77adda01286bcc96c910a0457b9a144454b8e" || challenger.Reranker == nil || challenger.Reranker.BindingState != evaluationObjectBindingExact || challenger.Reranker.ModelRevision == nil || *challenger.Reranker.ModelRevision != "4b0e5e6594de720a793646c0af2cfd52f8a45fa6" || challenger.Reranker.ServingRuntimeImageSHA256 == nil || *challenger.Reranker.ServingRuntimeImageSHA256 != "sha256:cc13f88dc249cb94ab30cab90286b0c72a329e3d605da497bd4e594c5d21af00" || challenger.Reranker.BaseDeploymentRevisionSHA != "3e477e25b55f814b65646e1a76339b23b0c85198" || challenger.Reranker.ProvenanceDeployment.BindingState != evaluationObjectBindingRequired || challenger.Reranker.ProvenanceDeployment.RevisionSHA != nil || challenger.Reranker.SignalDerivationProfile != hybridRerankingContract {
		t.Fatal("CPU reranker definition lost its exact deployment, model or scorer boundary")
	}
	if reranker.Profiles[1].Scorer.BindingState != evaluationObjectBindingExact || reranker.Profiles[1].Scorer.ScorerRevision == nil || *reranker.Profiles[1].Scorer.ScorerRevision != evaluatorRevision || reranker.Profiles[1].Scorer.ScorerArtifactSHA256 == nil || *reranker.Profiles[1].Scorer.ScorerArtifactSHA256 != *challenger.Scorer.ScorerArtifactSHA256 {
		t.Fatal("fusion-only baseline lost its exact scorer-artifact boundary")
	}
	if reranker.Authority.CallerLaneSelectionAllowed || reranker.Authority.ScorerMayGrantAuthority || reranker.Authority.FailedLaneSuppressionAllowed || !reranker.Authority.ExactCitationsRequired {
		t.Fatal("paired definition weakened authority isolation")
	}
	for _, evaluationCase := range reranker.Cases {
		if evaluationCase.QuerySignal == nil || evaluationCase.QuerySignal.BindingState != evaluationObjectBindingExact || evaluationCase.LaneQuerySignals != nil || evaluationCase.ChallengerQuerySignal == nil || evaluationCase.ChallengerQuerySignal.BindingState != evaluationObjectBindingRequired || len(evaluationCase.ExpectedEvidence) != 1 || evaluationCase.ExpectedEvidence[0].SelectorType != "span_id" {
			t.Fatalf("paired case %s is not bound to an exact held-out span", evaluationCase.CaseID)
		}
	}

	pairedFusion := readExpandedEvaluationDefinitionCore(t, pairedFusionDefinitionFixture)
	pairedLane := pairedFusion.Inputs.Lanes[0]
	if pairedFusion.SchemaVersion != retrievalEvaluationDefinitionV3 || pairedFusion.Inputs.ReferenceSuiteID != nil || pairedFusion.Inputs.ReferenceSuiteDocumentSHA256 != nil || pairedFusion.Inputs.QuerySignalBindingLedger != nil || pairedLane.Objects != nil || pairedLane.ObjectBindings == nil || pairedLane.ObjectBindings.Generation.BindingState != evaluationObjectBindingRequired || pairedLane.ObjectBindings.AdmissionPolicy.BindingState != evaluationObjectBindingExact {
		t.Fatal("paired fusion definition lost its blocked exact-generation/reference-suite boundary")
	}
	challengerFusion := pairedFusion.Profiles[0]
	baselineFusion := pairedFusion.Profiles[1]
	if challengerFusion.Role != "challenger" || challengerFusion.Mode != "fusion_only" || challengerFusion.FusionProfile != championFusionProfile || challengerFusion.FusionProfileObject == nil || challengerFusion.FusionProfileObject.BindingState != evaluationObjectBindingRequired || challengerFusion.FusionProfileObject.ProfileID != nil || challengerFusion.FusionProfileObject.DocumentSHA256 != nil || challengerFusion.Scorer.BindingState != evaluationObjectBindingRequired || baselineFusion.Role != "baseline" || baselineFusion.Mode != "fusion_only" || baselineFusion.FusionProfile != hybridFusionProfile || baselineFusion.FusionProfileObject != nil || baselineFusion.Scorer.BindingState != evaluationObjectBindingRequired || challengerFusion.ResourceLimits != baselineFusion.ResourceLimits {
		t.Fatal("paired fusion definition lost its isolated versioned profile boundary")
	}
	seenInjection := false
	for _, evaluationCase := range pairedFusion.Cases {
		if evaluationCase.QuerySignal == nil || evaluationCase.QuerySignal.BindingState != evaluationObjectBindingRequired || evaluationCase.ChallengerQuerySignal == nil || evaluationCase.ChallengerQuerySignal.BindingState != evaluationObjectBindingRequired || evaluationCase.LaneQuerySignals != nil || len(evaluationCase.ExpectedEvidence) != 1 || evaluationCase.ExpectedEvidence[0].SelectorType != "source_path" || evaluationCase.ExpectedEvidence[0].SpanID != nil {
			t.Fatalf("paired fusion case %s is not a frozen source judgment with two blocked query signals", evaluationCase.CaseID)
		}
		seenInjection = seenInjection || evaluationCase.Scenario == "prompt_injection"
	}
	if !seenInjection {
		t.Fatal("paired fusion definition lost its prompt-injection case")
	}

	federation := readExpandedEvaluationDefinitionCore(t, federationDefinitionFixture)
	if federation.SchemaVersion != retrievalEvaluationDefinitionV3 || federation.Inputs.QuerySignalBindingLedger == nil || federation.Inputs.QuerySignalBindingLedger.DocumentSHA256 != "sha256:2cc2040a4653ef4cc269179c5eed41b00a991bd4e8d5d4e8ebfd6c58ce93bc9e" || federation.Inputs.QuerySignalBindingLedger.RecordCount != 26 {
		t.Fatal("federation definition lost its exact 26-row query-signal ledger binding")
	}
	wantCommits := []string{"838d4e792be666ec11bd0c80331e0c5511b5010e", "9aeb47ce10339f4a14819335c6a00027353ba0df"}
	wantPolicyIDs := []string{
		"retrieval-admission:sha256:15ae0db5c197fb5c170c4e57dc87e2ef5b3a1c5901318192b6719bba1dba4c5d",
		"retrieval-admission:sha256:271621cf16a5e49b93006363680ed04e0885caafde9e9f7a8715f70db13966ae",
	}
	wantPolicyDocuments := []string{
		"sha256:12f4cb7f195952330f77b2c19c1991465aca69e81011d4bf00829ac0d03074e6",
		"sha256:21765b1c6129b8a33d39212ff2a9e1053cdbdb51a8ff695994b3d182dccece34",
	}
	for index, lane := range federation.Inputs.Lanes {
		if lane.SourceCommitSHA != wantCommits[index] || lane.Objects != nil || lane.ObjectBindings == nil || lane.ObjectBindings.Generation.BindingState != evaluationObjectBindingRequired || lane.ObjectBindings.Generation.GenerationID != nil || lane.ObjectBindings.Generation.GenerationDocumentSHA256 != nil || lane.ObjectBindings.AdmissionPolicy.BindingState != evaluationObjectBindingExact || lane.ObjectBindings.AdmissionPolicy.AdmissionPolicyID == nil || *lane.ObjectBindings.AdmissionPolicy.AdmissionPolicyID != wantPolicyIDs[index] || lane.ObjectBindings.AdmissionPolicy.AdmissionPolicyDocumentSHA256 == nil || *lane.ObjectBindings.AdmissionPolicy.AdmissionPolicyDocumentSHA256 != wantPolicyDocuments[index] {
			t.Fatalf("future lane %s does not preserve its exact source admission and unsigned generation boundary", lane.LaneID)
		}
	}
	federationScorer := federation.Profiles[0].Scorer
	if federation.Profiles[0].FusionProfile != "bounded_borda_v1" || federation.Profiles[0].Mode != "federated_fusion" || federationScorer.BindingState != evaluationObjectBindingExact || federationScorer.ScorerRevision == nil || *federationScorer.ScorerRevision != "0.4.1" || federationScorer.ScorerArtifactSHA256 == nil || *federationScorer.ScorerArtifactSHA256 != "sha256:4cdae7f913ce99fdddad697495bfe66b308bd5a1af9868da6e720df71a6f4150" {
		t.Fatal("future multi-lane definition lost the deterministic federation scorer")
	}
	seenPath := false
	seenArtifacts := make(map[string]string)
	seenDocuments := make(map[string]string)
	bindingCount := 0
	failureCaseCount := 0
	for _, evaluationCase := range federation.Cases {
		if evaluationCase.QuerySignal != nil || len(evaluationCase.LaneQuerySignals) != len(federation.Inputs.Lanes) {
			t.Fatalf("federation case %s does not use the complete per-lane query-signal shape", evaluationCase.CaseID)
		}
		if evaluationCase.Scenario != "normal" {
			failureCaseCount++
		}
		for laneIndex, laneSignal := range evaluationCase.LaneQuerySignals {
			wantLane := federation.Inputs.Lanes[laneIndex].LaneID
			if laneSignal.LaneID != wantLane || laneSignal.QuerySignal.BindingState != evaluationObjectBindingExact || laneSignal.QuerySignal.ArtifactID == nil || laneSignal.QuerySignal.DocumentSHA256 == nil {
				t.Fatalf("federation case %s lane %s lost its exact query-signal binding", evaluationCase.CaseID, wantLane)
			}
			owner := evaluationCase.CaseID + "/" + wantLane
			if previous := seenArtifacts[*laneSignal.QuerySignal.ArtifactID]; previous != "" {
				t.Fatalf("query-signal artifact is aliased by %s and %s", previous, owner)
			}
			seenArtifacts[*laneSignal.QuerySignal.ArtifactID] = owner
			if previous := seenDocuments[*laneSignal.QuerySignal.DocumentSHA256]; previous != "" {
				t.Fatalf("query-signal document is aliased by %s and %s", previous, owner)
			}
			seenDocuments[*laneSignal.QuerySignal.DocumentSHA256] = owner
			bindingCount++
		}
		for _, expected := range evaluationCase.ExpectedEvidence {
			seenPath = seenPath || expected.SelectorType == "source_path"
		}
	}
	if !seenPath {
		t.Fatal("future multi-lane definition has no commit-bound source-path expectations")
	}
	if bindingCount != 26 || len(seenArtifacts) != 26 || len(seenDocuments) != 26 || failureCaseCount != 6 {
		t.Fatalf("federation definition dropped or aliased its 26 signal bindings or six failure cases: bindings=%d artifacts=%d documents=%d failures=%d", bindingCount, len(seenArtifacts), len(seenDocuments), failureCaseCount)
	}
}

func TestExpandedEvaluationDefinitionMaterializationIsDeterministicAndImmutable(t *testing.T) {
	for _, fixture := range []string{rerankerDefinitionFixture, pairedFusionDefinitionFixture, legacyFederationDefinitionFixture, federationV2DefinitionFixture, federationDefinitionFixture} {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			store := filepath.Join(t.TempDir(), "store")
			first, firstPath, err := MaterializeExpandedEvaluationDefinition(fixture, store)
			if err != nil {
				t.Fatal(err)
			}
			second, secondPath, err := MaterializeExpandedEvaluationDefinition(fixture, store)
			if err != nil {
				t.Fatal(err)
			}
			if first.DefinitionID != second.DefinitionID || firstPath != secondPath {
				t.Fatal("identical frozen definition did not reuse its immutable CAS object")
			}
			info, err := os.Stat(firstPath)
			if err != nil || info.Mode().Perm() != 0o444 {
				t.Fatalf("materialized definition is not mode 0444: %v %v", info, err)
			}
		})
	}
}

func TestExpandedEvaluationDefinitionRejectsAuthorityAndBindingDrift(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		mutate  func(*RetrievalExpandedEvaluationDefinitionCore)
	}{
		{name: "premature ready", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.ExecutionState = "ready" }},
		{name: "paired fusion premature ready", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.ExecutionState = "ready" }},
		{name: "paired fusion wrong schema", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.SchemaVersion = retrievalEvaluationDefinitionV2
		}},
		{name: "paired fusion partial reference suite", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.ReferenceSuiteID = stringPointer("retrieval-evaluation-suite:sha256:" + strings.Repeat("1", 64))
		}},
		{name: "paired fusion unexpected query-signal ledger", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.QuerySignalBindingLedger = &RetrievalEvaluationBindingLedger{DocumentSHA256: "sha256:" + strings.Repeat("1", 64), RecordCount: len(core.Cases)}
		}},
		{name: "paired fusion challenger profile substitution", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].FusionProfile = hybridFusionProfile
			core.Profiles[0].Scorer.ScorerID = hybridFusionProfile
		}},
		{name: "paired fusion missing profile object", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].FusionProfileObject = nil
		}},
		{name: "paired fusion partial profile object", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].FusionProfileObject.ProfileID = stringPointer("fusion-profile:sha256:" + strings.Repeat("1", 64))
		}},
		{name: "paired fusion baseline profile object", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[1].FusionProfileObject = &RetrievalEvaluationFusionProfileBinding{BindingState: evaluationObjectBindingRequired}
		}},
		{name: "paired fusion baseline profile substitution", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[1].FusionProfile = championFusionProfile
			core.Profiles[1].Scorer.ScorerID = championFusionProfile
		}},
		{name: "paired fusion nonisolated window", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.Profiles[0].FusionWindow-- }},
		{name: "paired fusion nonisolated resource ceiling", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.Profiles[0].ResourceLimits.MaxExecutions-- }},
		{name: "paired fusion zero quality gain", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.ComparisonGates.MinimumNDCGGainPPM = 0 }},
		{name: "paired fusion missing baseline signal", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.Cases[0].QuerySignal = nil }},
		{name: "paired fusion partial baseline signal", fixture: pairedFusionDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].QuerySignal.ArtifactID = stringPointer("query-signal-artifact:sha256:" + strings.Repeat("1", 64))
		}},
		{name: "exact admissions cannot imply ready generations", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.ExecutionState = "ready" }},
		{name: "cross generation scoring", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.CrossGenerationScoreComparison = true
		}},
		{name: "caller authority selection", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Authority.CallerLaneSelectionAllowed = true
		}},
		{name: "scorer grants authority", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.Authority.ScorerMayGrantAuthority = true }},
		{name: "failed lane hidden", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Authority.FailedLaneSuppressionAllowed = true
		}},
		{name: "partial exact lane", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.Inputs.Lanes[0].Objects.GenerationID = nil }},
		{name: "partial exact generation lane", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.Lanes[0].ObjectBindings.Generation.BindingState = evaluationObjectBindingExact
			core.Inputs.Lanes[0].ObjectBindings.Generation.GenerationID = stringPointer("retrieval-generation:sha256:" + strings.Repeat("1", 64))
		}},
		{name: "partial exact admission-policy lane", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.Lanes[0].ObjectBindings.AdmissionPolicy.AdmissionPolicyDocumentSHA256 = nil
		}},
		{name: "v3 lane uses legacy combined objects", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.Lanes[0].Objects = &RetrievalEvaluationObjectBinding{BindingState: evaluationObjectBindingRequired}
			core.Inputs.Lanes[0].ObjectBindings = nil
		}},
		{name: "v2 lane uses split objects", fixture: federationV2DefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.Lanes[0].Objects = nil
			core.Inputs.Lanes[0].ObjectBindings = &RetrievalEvaluationLaneObjectBindings{
				Generation:      RetrievalEvaluationGenerationBinding{BindingState: evaluationObjectBindingRequired},
				AdmissionPolicy: RetrievalEvaluationAdmissionPolicyBinding{BindingState: evaluationObjectBindingRequired},
			}
		}},
		{name: "v3 lane mixes combined and split objects", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.Lanes[0].Objects = &RetrievalEvaluationObjectBinding{BindingState: evaluationObjectBindingRequired}
		}},
		{name: "federation admission-policy identity aliases another lane", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.Lanes[1].ObjectBindings.AdmissionPolicy.AdmissionPolicyID = core.Inputs.Lanes[0].ObjectBindings.AdmissionPolicy.AdmissionPolicyID
		}},
		{name: "federation admission-policy document aliases another lane", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.Lanes[1].ObjectBindings.AdmissionPolicy.AdmissionPolicyDocumentSHA256 = core.Inputs.Lanes[0].ObjectBindings.AdmissionPolicy.AdmissionPolicyDocumentSHA256
		}},
		{name: "federation generation identity aliases another lane", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			bindSyntheticExactEvaluationGeneration(&core.Inputs.Lanes[0].ObjectBindings.Generation, '1', '2')
			bindSyntheticExactEvaluationGeneration(&core.Inputs.Lanes[1].ObjectBindings.Generation, '1', '3')
		}},
		{name: "federation generation document aliases another lane", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			bindSyntheticExactEvaluationGeneration(&core.Inputs.Lanes[0].ObjectBindings.Generation, '1', '2')
			bindSyntheticExactEvaluationGeneration(&core.Inputs.Lanes[1].ObjectBindings.Generation, '3', '2')
		}},
		{name: "partial exact reranker", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].Reranker.ModelInventorySHA256 = nil
		}},
		{name: "missing serving runtime digest", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].Reranker.ServingRuntimeImageSHA256 = nil
		}},
		{name: "missing scorer derivation profile", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].Reranker.SignalDerivationProfile = ""
		}},
		{name: "partial provenance deployment", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].Reranker.ProvenanceDeployment.RevisionSHA = stringPointer(strings.Repeat("5", 40))
		}},
		{name: "partial exact scorer", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].Scorer.ScorerArtifactSHA256 = nil
		}},
		{name: "partial required challenger signal", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].ChallengerQuerySignal.ArtifactID = stringPointer("query-signal-artifact:sha256:" + strings.Repeat("4", 64))
		}},
		{name: "missing challenger signal binding", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].ChallengerQuerySignal = nil
		}},
		{name: "challenger signal reuses fusion-only signal", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			copy := *core.Cases[0].QuerySignal
			core.Cases[0].ChallengerQuerySignal = &copy
		}},
		{name: "unexpected federation challenger signal", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			copy := core.Cases[0].LaneQuerySignals[0].QuerySignal
			core.Cases[0].ChallengerQuerySignal = &copy
		}},
		{name: "partial exact federation scorer", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].Scorer.ScorerArtifactSHA256 = nil
		}},
		{name: "partial required query signal", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].LaneQuerySignals[0].QuerySignal.BindingState = evaluationObjectBindingRequired
		}},
		{name: "unresolved lane signal despite exact ledger", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].LaneQuerySignals[0].QuerySignal = RetrievalEvaluationQuerySignalBinding{BindingState: evaluationObjectBindingRequired}
		}},
		{name: "legacy singular federation signal made exact", fixture: legacyFederationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].QuerySignal = &RetrievalEvaluationQuerySignalBinding{
				BindingState:   evaluationObjectBindingExact,
				ArtifactID:     stringPointer("query-signal-artifact:sha256:" + strings.Repeat("1", 64)),
				DocumentSHA256: stringPointer("sha256:" + strings.Repeat("2", 64)),
			}
		}},
		{name: "missing federation lane query signal", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].LaneQuerySignals = core.Cases[0].LaneQuerySignals[:1]
		}},
		{name: "duplicate federation lane query signal", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].LaneQuerySignals[1].LaneID = core.Cases[0].LaneQuerySignals[0].LaneID
		}},
		{name: "wrong-lane federation query lineage", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[1].LaneQuerySignals[0].HybridCandidateID = core.Cases[1].LaneQuerySignals[1].HybridCandidateID
			core.Cases[1].LaneQuerySignals[0].DenseArtifactID = core.Cases[1].LaneQuerySignals[1].DenseArtifactID
		}},
		{name: "federation signal artifact aliased across lanes", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].LaneQuerySignals[1].QuerySignal.ArtifactID = core.Cases[0].LaneQuerySignals[0].QuerySignal.ArtifactID
		}},
		{name: "federation signal document aliased across lanes", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].LaneQuerySignals[1].QuerySignal.DocumentSHA256 = core.Cases[0].LaneQuerySignals[0].QuerySignal.DocumentSHA256
		}},
		{name: "federation lane query signals reordered", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].LaneQuerySignals[0], core.Cases[0].LaneQuerySignals[1] = core.Cases[0].LaneQuerySignals[1], core.Cases[0].LaneQuerySignals[0]
		}},
		{name: "singular and multi-lane federation signals combined", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			copy := core.Cases[0].LaneQuerySignals[0].QuerySignal
			core.Cases[0].QuerySignal = &copy
		}},
		{name: "failure case drops unavailable lane signal", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			for index := range core.Cases {
				if core.Cases[index].Scenario == "lane_unavailable" {
					core.Cases[index].LaneQuerySignals = core.Cases[index].LaneQuerySignals[1:]
					return
				}
			}
		}},
		{name: "federation binding ledger count drift", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.QuerySignalBindingLedger.RecordCount--
		}},
		{name: "invalid federation binding ledger hash", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.QuerySignalBindingLedger.DocumentSHA256 = "sha256:0"
		}},
		{name: "query substitution", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.Cases[0].Query += " changed" }},
		{name: "case reorder", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0], core.Cases[1] = core.Cases[1], core.Cases[0]
		}},
		{name: "unknown lane", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.Cases[0].RequiredLaneIDs[0] = "unknown" }},
		{name: "source commit substitution", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[3].ExpectedEvidence[0].SourceCommitSHA = strings.Repeat("0", 40)
		}},
		{name: "missing injection gate", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			filtered := core.Cases[:0]
			for _, evaluationCase := range core.Cases {
				if evaluationCase.CaseID != "case-workflows-injection" {
					filtered = append(filtered, evaluationCase)
				}
			}
			core.Cases = filtered
		}},
		{name: "binding field omission", fixture: federationDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.RequiredExactBindingFields = core.Inputs.RequiredExactBindingFields[:5]
		}},
		{name: "zero resource budget", fixture: rerankerDefinitionFixture, mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles[0].ResourceLimits.MaxCPUTimeMillisPerExecution = 0
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := readExpandedEvaluationDefinitionCore(t, test.fixture)
			test.mutate(&core)
			if _, err := sealExpandedEvaluationDefinition(core); err == nil {
				t.Fatal("mutated expanded evaluation definition was accepted")
			}
		})
	}
}

func TestExpandedEvaluationDefinitionRejectsUnboundedStructures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RetrievalExpandedEvaluationDefinitionCore)
	}{
		{name: "metadata string", mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) { core.Name = strings.Repeat("x", 513) }},
		{name: "lane count", mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Inputs.Lanes = make([]RetrievalEvaluationLaneDefinition, maxEvaluationDefinitionInputs+1)
		}},
		{name: "profile count", mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Profiles = make([]RetrievalEvaluationProfileDefinition, maxEvaluationDefinitionProfiles+1)
		}},
		{name: "case count", mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases = make([]RetrievalExpandedEvaluationCase, maxEvaluationDefinitionCases+1)
		}},
		{name: "query bytes", mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].Query = strings.Repeat("q", 16*1024+1)
		}},
		{name: "gate list", mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].RequiredGates = make([]string, len(evaluationCaseGates)+1)
		}},
		{name: "evidence list", mutate: func(core *RetrievalExpandedEvaluationDefinitionCore) {
			core.Cases[0].ExpectedEvidence = make([]RetrievalEvaluationEvidenceExpectation, 1001)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := readExpandedEvaluationDefinitionCore(t, rerankerDefinitionFixture)
			test.mutate(&core)
			if _, err := sealExpandedEvaluationDefinition(core); err == nil {
				t.Fatal("unbounded expanded evaluation structure was accepted")
			}
		})
	}
}

func TestExpandedEvaluationDefinitionInputIsBoundedStrictCanonicalJSON(t *testing.T) {
	fixtureBytes, err := os.ReadFile(rerankerDefinitionFixture)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "duplicate key",
			data: []byte(strings.Replace(string(fixtureBytes), "  \"schema_version\": \"1.0.0\",", "  \"schema_version\": \"1.0.0\",\n  \"schema_version\": \"1.0.0\",", 1)),
		},
		{
			name: "noncanonical encoding",
			data: []byte(strings.Replace(string(fixtureBytes), "{\n  \"schema_version\"", "{\"schema_version\"", 1)),
		},
		{
			name: "size ceiling",
			data: []byte(strings.Repeat(" ", int(maxEvaluationDefinitionBytes)+1)),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			corePath := filepath.Join(t.TempDir(), "core.json")
			if err := os.WriteFile(corePath, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := MaterializeExpandedEvaluationDefinition(corePath, t.TempDir()); err == nil {
				t.Fatal("invalid expanded evaluation input was accepted")
			}
		})
	}
}

func TestExpandedEvaluationDefinitionCanBecomeReadyOnlyWithCompleteExactBindings(t *testing.T) {
	reranker := readExpandedEvaluationDefinitionCore(t, rerankerDefinitionFixture)
	bindExactEvaluationScorers(reranker.Profiles)
	bindExactChallengerQuerySignals(reranker.Cases)
	exactReranker := reranker.Profiles[0].Reranker
	exactReranker.BindingState = evaluationObjectBindingExact
	exactReranker.ModelRevision = stringPointer("revision:immutable-test")
	exactReranker.ModelArtifactSHA256 = stringPointer("sha256:" + strings.Repeat("1", 64))
	exactReranker.ModelInventorySHA256 = stringPointer("sha256:" + strings.Repeat("3", 64))
	exactReranker.TokenizerID = stringPointer("tokenizer:immutable-test")
	exactReranker.TokenizerArtifactSHA256 = stringPointer("sha256:" + strings.Repeat("2", 64))
	exactReranker.ServingRuntimeImageSHA256 = stringPointer("sha256:" + strings.Repeat("4", 64))
	exactReranker.ProvenanceDeployment = RetrievalEvaluationRevisionBinding{
		BindingState: evaluationObjectBindingExact,
		RevisionSHA:  stringPointer(strings.Repeat("5", 40)),
	}
	reranker.ExecutionState = "ready"
	if _, err := sealExpandedEvaluationDefinition(reranker); err != nil {
		t.Fatalf("complete exact reranker bindings did not make the definition ready: %v", err)
	}

	pairedFusion := readExpandedEvaluationDefinitionCore(t, pairedFusionDefinitionFixture)
	pairedFusion.Inputs.ReferenceSuiteID = stringPointer("retrieval-evaluation-suite:sha256:" + strings.Repeat("6", 64))
	pairedFusion.Inputs.ReferenceSuiteDocumentSHA256 = stringPointer("sha256:" + strings.Repeat("7", 64))
	bindSyntheticExactEvaluationGeneration(&pairedFusion.Inputs.Lanes[0].ObjectBindings.Generation, '8', '9')
	bindExactEvaluationScorers(pairedFusion.Profiles)
	pairedFusion.Profiles[0].FusionProfileObject = &RetrievalEvaluationFusionProfileBinding{
		BindingState:   evaluationObjectBindingExact,
		ProfileID:      stringPointer("fusion-profile:sha256:" + strings.Repeat("a", 64)),
		DocumentSHA256: stringPointer("sha256:" + strings.Repeat("b", 64)),
	}
	bindExactPairedQuerySignals(pairedFusion.Cases)
	pairedFusion.ExecutionState = "ready"
	if _, err := sealExpandedEvaluationDefinition(pairedFusion); err != nil {
		t.Fatalf("complete paired fusion bindings did not make the definition ready: %v", err)
	}

	federation := readExpandedEvaluationDefinitionCore(t, federationDefinitionFixture)
	bindExactEvaluationScorers(federation.Profiles)
	for index := range federation.Inputs.Lanes {
		bindSyntheticExactEvaluationGeneration(&federation.Inputs.Lanes[index].ObjectBindings.Generation, rune('3'+index), rune('5'+index))
	}
	federation.ExecutionState = "ready"
	if _, err := sealExpandedEvaluationDefinition(federation); err != nil {
		t.Fatalf("complete exact generations plus the two exact admissions and 26 frozen query-signal bindings did not make the definition ready: %v", err)
	}
}

func bindSyntheticExactEvaluationGeneration(binding *RetrievalEvaluationGenerationBinding, identityByte, documentByte rune) {
	binding.BindingState = evaluationObjectBindingExact
	binding.GenerationID = stringPointer("retrieval-generation:sha256:" + strings.Repeat(string(identityByte), 64))
	binding.GenerationDocumentSHA256 = stringPointer("sha256:" + strings.Repeat(string(documentByte), 64))
}

func bindExactEvaluationScorers(profiles []RetrievalEvaluationProfileDefinition) {
	for index := range profiles {
		profiles[index].Scorer.BindingState = evaluationObjectBindingExact
		profiles[index].Scorer.ScorerRevision = stringPointer("revision:immutable-test")
		profiles[index].Scorer.ScorerArtifactSHA256 = stringPointer(digestBytes([]byte(profiles[index].ProfileID)))
	}
}

func bindExactChallengerQuerySignals(cases []RetrievalExpandedEvaluationCase) {
	for index := range cases {
		cases[index].ChallengerQuerySignal = &RetrievalEvaluationQuerySignalBinding{
			BindingState:   evaluationObjectBindingExact,
			ArtifactID:     stringPointer("query-signal-artifact:" + digestBytes([]byte("challenger:"+cases[index].CaseID))),
			DocumentSHA256: stringPointer(digestBytes([]byte("challenger-document:" + cases[index].Query))),
		}
	}
}

func bindExactPairedQuerySignals(cases []RetrievalExpandedEvaluationCase) {
	for index := range cases {
		cases[index].QuerySignal = &RetrievalEvaluationQuerySignalBinding{
			BindingState:   evaluationObjectBindingExact,
			ArtifactID:     stringPointer("query-signal-artifact:" + digestBytes([]byte("baseline:"+cases[index].CaseID))),
			DocumentSHA256: stringPointer(digestBytes([]byte("baseline-document:" + cases[index].Query))),
		}
		cases[index].ChallengerQuerySignal = &RetrievalEvaluationQuerySignalBinding{
			BindingState:   evaluationObjectBindingExact,
			ArtifactID:     stringPointer("query-signal-artifact:" + digestBytes([]byte("challenger:"+cases[index].CaseID))),
			DocumentSHA256: stringPointer(digestBytes([]byte("challenger-document:" + cases[index].Query))),
		}
	}
}

func readExpandedEvaluationDefinitionCore(t *testing.T, fixture string) RetrievalExpandedEvaluationDefinitionCore {
	t.Helper()
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var core RetrievalExpandedEvaluationDefinitionCore
	if err := decodeStrictCanonical(data, &core); err != nil {
		t.Fatalf("decode frozen expanded evaluation fixture %s: %v", fixture, err)
	}
	return core
}
