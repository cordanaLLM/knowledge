package main

import (
	"path/filepath"
)

func validateCurrentGenerationState(stateRoot, storeRoot string, required bool) (*RetrievalGenerationPointer, []byte, error) {
	pointer, aliasBytes, err := readCurrentPointer(stateRoot, required)
	if err != nil || pointer == nil {
		return pointer, aliasBytes, err
	}
	pointerHash := digestBytes(aliasBytes)
	immutable, immutableBytes, err := loadImmutablePointer(stateRoot, pointer.PointerID, pointerHash)
	if err != nil || !bytesEqual(aliasBytes, immutableBytes) || immutable.PointerID != pointer.PointerID {
		return nil, nil, lifecycleFailure("pointer-alias-mismatch", "pointer alias does not equal its immutable object")
	}
	if err := verifyPointerChain(stateRoot, storeRoot, immutable, pointerHash, map[string]bool{}, 0); err != nil {
		return nil, nil, err
	}
	return &immutable, immutableBytes, nil
}

func verifyPointerChain(stateRoot, storeRoot string, pointer RetrievalGenerationPointer, expectedHash string, visited map[string]bool, depth int) error {
	if depth >= maxLifecycleDepth {
		return lifecycleFailure("generation-chain-too-deep", "retrieval generation chain exceeds its bound")
	}
	if visited[pointer.PointerID] {
		return lifecycleFailure("generation-chain-cycle", "retrieval generation chain contains a cycle")
	}
	visited[pointer.PointerID] = true
	defer delete(visited, pointer.PointerID)
	if validateGenerationPointer(pointer) != nil {
		return lifecycleFailure("pointer-invalid", "retrieval generation pointer is invalid")
	}
	pointerHash, pointerBytes, err := documentSHA256(pointer)
	if err != nil || pointerHash != expectedHash {
		return lifecycleFailure("pointer-hash-mismatch", "retrieval generation pointer hash differs")
	}
	immutable, immutableBytes, err := loadImmutablePointer(stateRoot, pointer.PointerID, expectedHash)
	if err != nil || !bytesEqual(pointerBytes, immutableBytes) || immutable.PointerID != pointer.PointerID {
		return lifecycleFailure("pointer-immutable-mismatch", "retrieval generation pointer immutable object differs")
	}

	current, _, err := loadStateGeneration(stateRoot, storeRoot, pointer.CurrentGenerationID, pointer.CurrentGenerationSHA256)
	if err != nil {
		return err
	}
	if current.LexicalProfile != pointer.CurrentLexicalProfile || current.LexicalTokenizerID != pointer.CurrentLexicalTokenizerID || current.LexicalScorerID != pointer.CurrentLexicalScorerID {
		return lifecycleFailure("pointer-profile-mismatch", "current pointer lexical profile differs from its generation")
	}
	if pointer.PreviousGenerationID != nil {
		previous, _, err := loadStateGeneration(stateRoot, storeRoot, *pointer.PreviousGenerationID, *pointer.PreviousGenerationSHA256)
		if err != nil {
			return err
		}
		if previous.LexicalProfile == "" {
			if pointer.PreviousLexicalProfile != nil || pointer.PreviousLexicalTokenizerID != nil || pointer.PreviousLexicalScorerID != nil {
				return lifecycleFailure("pointer-profile-mismatch", "legacy previous generation has successor pointer lineage")
			}
		} else if pointer.PreviousLexicalProfile == nil || pointer.PreviousLexicalTokenizerID == nil || pointer.PreviousLexicalScorerID == nil || previous.LexicalProfile != *pointer.PreviousLexicalProfile || previous.LexicalTokenizerID != *pointer.PreviousLexicalTokenizerID || previous.LexicalScorerID != *pointer.PreviousLexicalScorerID {
			return lifecycleFailure("pointer-profile-mismatch", "previous pointer lexical profile differs from its generation")
		}
	}
	receipt, _, err := loadImmutableReceipt(stateRoot, pointer.TransitionReceiptID)
	if err != nil {
		return err
	}
	if receipt.ResultingPointerID != pointer.PointerID || receipt.ResultingPointerSHA256 != pointerHash || receipt.Intent.TargetGenerationID != pointer.CurrentGenerationID || receipt.Intent.TargetGenerationSHA256 != pointer.CurrentGenerationSHA256 || receipt.Intent.TransitionedAt != pointer.UpdatedAt {
		return lifecycleFailure("receipt-pointer-mismatch", "transition receipt and resulting pointer differ")
	}
	intentHash, intentBytes, err := documentSHA256(receipt.Intent)
	if err != nil || intentHash != receipt.IntentDocumentSHA256 {
		return lifecycleFailure("intent-hash-mismatch", "receipt intent whole-document hash differs")
	}
	signature, _, err := readBoundStoreDocument(stateRoot, receipt.SignaturePath, receipt.SignatureSHA256, receipt.SignatureByteSize, maxSignatureBytes)
	if err != nil || validateCanonicalSSHSIG(signature) != nil {
		return lifecycleFailure("signature-unavailable", "stored transition signature is unavailable")
	}
	allowedSigners, _, err := readBoundStoreDocument(stateRoot, receipt.AllowedSignersPath, receipt.AllowedSignersSHA256, receipt.AllowedSignersByteSize, maxAllowedSignersBytes)
	if err != nil || receipt.AllowedSignersSHA256 != receipt.Intent.Authorization.AllowedSignersSHA256 {
		return lifecycleFailure("authorization-policy-unavailable", "stored allowed signers policy is unavailable")
	}
	if _, err := readAndAuthorizeAllowedSignersBytes(allowedSigners, receipt.Intent.Authorization.Actor, receipt.Intent.Authorization.KeyID); err != nil {
		return lifecycleFailure("signer-not-authorized", "stored allowed signers policy no longer proves authorization")
	}
	if err := verifyDetachedSSHSIG(intentBytes, signature, allowedSigners, receipt.Intent.Authorization.Actor, receipt.Intent.Authorization.KeyID, receipt.Intent.Authorization.Namespace); err != nil {
		return lifecycleFailure("signature-verification-failed", "stored transition signature failed verification")
	}
	createdAt, _ := parseCanonicalUTC(current.CreatedAt)
	transitionedAt, _ := parseCanonicalUTC(receipt.Intent.TransitionedAt)
	if createdAt.After(transitionedAt) {
		return lifecycleFailure("generation-time-invalid", "generation was created after its transition")
	}
	historicalPolicyPath := filepath.Join(storeRoot, filepath.FromSlash(current.AdmissionPolicyPath))
	historicalPolicy, _, err := loadCurrentAdmissionPolicy(historicalPolicyPath, current.AdmissionPolicySHA256, receipt.Intent.TransitionedAt)
	if err != nil || !generationMatchesPolicy(current, historicalPolicy, current.AdmissionPolicySHA256) {
		return lifecycleFailure("historical-policy-invalid", "generation policy was not valid at transition time")
	}

	intent := receipt.Intent
	if intent.PriorPointerID == nil {
		if pointer.Revision != 1 || pointer.PreviousGenerationID != nil || intent.Decision != "promoted" || intent.RollbackOfReceiptID != nil || current.BaseGenerationID != nil {
			return lifecycleFailure("bootstrap-chain-invalid", "bootstrap transition chain is inconsistent")
		}
		return nil
	}
	prior, priorBytes, err := loadImmutablePointer(stateRoot, *intent.PriorPointerID, *intent.PriorPointerSHA256)
	if err != nil {
		return err
	}
	if err := verifyPointerChain(stateRoot, storeRoot, prior, digestBytes(priorBytes), visited, depth+1); err != nil {
		return err
	}
	priorTime, _ := parseCanonicalUTC(prior.UpdatedAt)
	if pointer.Revision != prior.Revision+1 || !transitionedAt.After(priorTime) || pointer.PreviousGenerationID == nil || *pointer.PreviousGenerationID != prior.CurrentGenerationID || *pointer.PreviousGenerationSHA256 != prior.CurrentGenerationSHA256 {
		return lifecycleFailure("pointer-chain-invalid", "generation pointer does not advance its exact prior pointer")
	}
	if intent.Decision == "promoted" {
		if intent.RollbackOfReceiptID != nil || current.BaseGenerationID == nil || *current.BaseGenerationID != prior.CurrentGenerationID || *current.BaseGenerationSHA256 != prior.CurrentGenerationSHA256 {
			return lifecycleFailure("promotion-chain-invalid", "promotion generation base differs from prior current")
		}
	} else {
		if prior.PreviousGenerationID == nil || intent.RollbackOfReceiptID == nil || *intent.RollbackOfReceiptID != prior.TransitionReceiptID || pointer.CurrentGenerationID != *prior.PreviousGenerationID || pointer.CurrentGenerationSHA256 != *prior.PreviousGenerationSHA256 {
			return lifecycleFailure("rollback-chain-invalid", "rollback did not restore the exact prior previous generation")
		}
	}
	return nil
}

func GetGenerationStatus(config GenerationStatusConfig) GenerationStatus {
	status := GenerationStatus{State: "backend_unavailable"}
	if lifecycleRequiredMissing(config.StoreRoot, config.StateRoot, config.AdmissionPolicyPath, config.AdmissionPolicyHash, config.AsOf) {
		status.ErrorCode = "status-input-invalid"
		return status
	}
	err := withGenerationLock(config.StateRoot, func() error {
		pointer, _, err := validateCurrentGenerationState(config.StateRoot, config.StoreRoot, false)
		if err != nil {
			return err
		}
		if pointer == nil {
			status = GenerationStatus{State: "empty", Revision: 0}
			return nil
		}
		current, _, err := loadStateGeneration(config.StateRoot, config.StoreRoot, pointer.CurrentGenerationID, pointer.CurrentGenerationSHA256)
		if err != nil {
			return err
		}
		policy, _, err := loadCurrentAdmissionPolicy(config.AdmissionPolicyPath, config.AdmissionPolicyHash, config.AsOf)
		if err != nil || !generationMatchesPolicy(current, policy, config.AdmissionPolicyHash) {
			return lifecycleFailure("current-policy-invalid", "current generation is not bound by a fresh caller-pinned policy")
		}
		currentID, currentHash, pointerID, receiptID, updatedAt := pointer.CurrentGenerationID, pointer.CurrentGenerationSHA256, pointer.PointerID, pointer.TransitionReceiptID, pointer.UpdatedAt
		status = GenerationStatus{
			State: "ok", CurrentGenerationID: &currentID, CurrentGenerationSHA256: &currentHash,
			PreviousGenerationID: pointer.PreviousGenerationID, PreviousGenerationSHA256: pointer.PreviousGenerationSHA256,
			PointerID: &pointerID, Revision: pointer.Revision, TransitionReceiptID: &receiptID, UpdatedAt: &updatedAt,
		}
		return nil
	})
	if err != nil {
		status.ErrorCode = lifecycleCode(err)
	}
	return status
}

// VerifyGenerationState succeeds only for states that genuinely mean verified.
// An absent generation store is not verified: a caller that can accept absence
// must request it explicitly through AllowAbsentGeneration.
func VerifyGenerationState(config GenerationStatusConfig) error {
	status := GetGenerationStatus(config)
	switch status.State {
	case "ok":
		return nil
	case "empty":
		if config.AllowAbsentGeneration {
			return nil
		}
		return lifecycleFailure("generation-absent", "no current retrieval generation exists to verify")
	default:
		code := status.ErrorCode
		if code == "" {
			code = "generation-state-unverified"
		}
		return lifecycleFailure(code, "retrieval generation state verification failed")
	}
}
