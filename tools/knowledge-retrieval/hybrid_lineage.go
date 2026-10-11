package main

import "errors"

// hybridDocumentBinding is the exact store binding whose bytes were decoded
// into one member of a hybrid candidate. Keeping these bindings beside the
// decoded values prevents semantic validation from silently accepting a valid
// object read from a path, digest or byte extent different from the candidate.
type hybridDocumentBinding struct {
	path   string
	digest string
	size   int64
}

type hybridLineageBindings struct {
	lexical hybridDocumentBinding
	index   hybridDocumentBinding
	dense   hybridDocumentBinding
	fusion  *hybridDocumentBinding
}

// validateLoadedHybridLineage is shared by the live query loader and frozen
// paired preflight. It validates the complete decoded lexical/index/dense
// lineage plus every path, whole-document hash, byte size, profile, admission,
// freshness, model, tokenizer, representation and count copied into the
// hybrid manifest. Callers must pass bindings for the exact bytes already read.
func validateLoadedHybridLineage(hybrid HybridCandidateManifest, lexical CandidateManifest, index LexicalIndex, dense DenseVectorArtifact, fusion *FusionProfile, bindings hybridLineageBindings) error {
	if err := validateHybridCandidate(hybrid); err != nil {
		return err
	}
	if err := validateCandidate(lexical); err != nil {
		return err
	}
	if err := validateIndex(index, lexical); err != nil {
		return err
	}
	if err := validateDenseArtifact(dense, lexical, index, hardMaxDenseDocuments, hardMaxDenseDimension); err != nil {
		return err
	}

	if bindings.lexical.path != hybrid.LexicalCandidatePath ||
		bindings.lexical.digest != hybrid.LexicalCandidateSHA256 ||
		bindings.lexical.size != hybrid.LexicalCandidateByteSize ||
		bindings.index.path != lexical.LexicalIndexPath ||
		bindings.index.digest != lexical.LexicalIndexSHA256 ||
		bindings.index.size != lexical.LexicalIndexByteSize ||
		bindings.dense.path != hybrid.DenseArtifactPath ||
		bindings.dense.digest != hybrid.DenseArtifactSHA256 ||
		bindings.dense.size != hybrid.DenseArtifactByteSize {
		return errors.New("hybrid candidate store binding mismatch")
	}

	if hybrid.LexicalCandidateID != lexical.ManifestID ||
		hybrid.LexicalIndexID != lexical.LexicalIndexID ||
		hybrid.LexicalProfile != lexical.LexicalProfile ||
		hybrid.LexicalTokenizerID != lexical.LexicalTokenizerID ||
		hybrid.LexicalScorerID != lexical.LexicalScorerID ||
		hybrid.SnapshotManifestID != lexical.SnapshotManifestID ||
		hybrid.EvidenceManifestID != lexical.EvidenceManifestID ||
		hybrid.AdmissionPolicyID != lexical.AdmissionPolicyID ||
		hybrid.AdmissionPolicySHA256 != lexical.AdmissionPolicySHA256 ||
		hybrid.SourceAdmissionMethod != lexical.SourceAdmissionMethod ||
		hybrid.SourceAdmissionPolicyID != lexical.SourceAdmissionPolicyID ||
		hybrid.SourceAdmissionPolicySHA256 != lexical.SourceAdmissionPolicySHA256 ||
		hybrid.FreshnessState != lexical.FreshnessState ||
		hybrid.EvaluatedAt != lexical.EvaluatedAt ||
		hybrid.FreshUntil != lexical.FreshUntil ||
		index.FreshnessState != lexical.FreshnessState ||
		!lineagesEqual(hybrid.Lineages, lexical.Lineages) {
		return errors.New("hybrid lexical, admission or freshness lineage mismatch")
	}

	if hybrid.DenseArtifactID != dense.ArtifactID ||
		hybrid.DenseModelID != dense.ModelID ||
		hybrid.DenseModelRevision != dense.ModelRevision ||
		hybrid.DenseModelArtifactSHA256 != dense.ModelArtifactSHA256 ||
		hybrid.DenseTokenizerID != dense.TokenizerID ||
		hybrid.DenseTokenizerSHA256 != dense.TokenizerSHA256 ||
		hybrid.EmbeddingProfile != dense.EmbeddingProfile ||
		hybrid.DenseDocumentInstruction != dense.DocumentInstruction ||
		hybrid.VectorEncoding != dense.VectorEncoding ||
		hybrid.Normalization != dense.Normalization ||
		hybrid.QuantizationScale != dense.QuantizationScale ||
		hybrid.Dimension != dense.Dimension ||
		hybrid.DocumentCount != dense.DocumentCount ||
		hybrid.DocumentCount != lexical.DocumentCount ||
		hybrid.DocumentCount != index.DocumentCount {
		return errors.New("hybrid dense model, tokenizer, representation or count lineage mismatch")
	}

	switch hybrid.FusionProfile {
	case hybridFusionProfile:
		if fusion != nil || bindings.fusion != nil {
			return errors.New("baseline hybrid candidate carries a fusion-profile object")
		}
	case championFusionProfile:
		if fusion == nil || bindings.fusion == nil {
			return errors.New("challenger hybrid candidate lacks its fusion-profile object")
		}
		if bindings.fusion.path != hybrid.FusionProfilePath ||
			bindings.fusion.digest != hybrid.FusionProfileSHA256 ||
			bindings.fusion.size != hybrid.FusionProfileByteSize ||
			fusion.ProfileID != hybrid.FusionProfileID {
			return errors.New("challenger fusion-profile store binding mismatch")
		}
		if err := validateFusionProfileLineage(*fusion, lexical, bindings.lexical.digest, dense, bindings.dense.digest); err != nil {
			return err
		}
	default:
		return errors.New("hybrid fusion profile unsupported")
	}
	return nil
}
