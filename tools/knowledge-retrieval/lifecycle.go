package main

import (
	"strings"
)

func PrepareGenerationPromotion(config PreparePromotionConfig) (RetrievalTransitionIntent, error) {
	var zero RetrievalTransitionIntent
	if lifecycleRequiredMissing(config.GenerationPath, config.GenerationHash, config.StoreRoot, config.StateRoot, config.AdmissionPolicyPath, config.AdmissionPolicyHash, config.AllowedSignersPath, config.Actor, config.KeyID, config.TransitionedAt) {
		return zero, lifecycleFailure("promotion-input-invalid", "promotion preparation requires every pinned input and state root")
	}
	if config.Bootstrap == (config.ExpectPointerID != "") {
		return zero, lifecycleFailure("promotion-mode-invalid", "select exactly one of bootstrap or expected pointer")
	}
	_, err := parseCanonicalUTC(config.TransitionedAt)
	if err != nil {
		return zero, lifecycleFailure("timestamp-invalid", "transition timestamp is not canonical UTC")
	}
	generation, _, err := loadAndVerifyGeneration(config.GenerationPath, config.GenerationHash, config.StoreRoot)
	if err != nil {
		return zero, lifecycleFailure("candidate-invalid", "evaluated candidate failed whole-generation verification")
	}
	policy, _, err := loadCurrentAdmissionPolicy(config.AdmissionPolicyPath, config.AdmissionPolicyHash, config.TransitionedAt)
	if err != nil || !generationMatchesPolicy(generation, policy, config.AdmissionPolicyHash) {
		return zero, lifecycleFailure("admission-policy-invalid", "current admission policy is stale or does not bind the candidate")
	}
	allowedSigners, err := readAndAuthorizeAllowedSigners(config.AllowedSignersPath, config.Actor, config.KeyID)
	if err != nil {
		return zero, lifecycleFailure("signer-not-authorized", err.Error())
	}
	var intent RetrievalTransitionIntent
	err = withGenerationLock(config.StateRoot, func() error {
		pointer, pointerBytes, err := validateCurrentGenerationState(config.StateRoot, config.StoreRoot, false)
		if err != nil {
			return err
		}
		var priorID, priorHash *string
		if config.Bootstrap {
			if pointer != nil {
				return lifecycleFailure("bootstrap-conflict", "bootstrap requires an empty generation state")
			}
			if generation.BaseGenerationID != nil {
				return lifecycleFailure("promotion-base-mismatch", "bootstrap generation base must be null")
			}
		} else {
			if pointer == nil || pointer.PointerID != config.ExpectPointerID {
				return lifecycleFailure("cas-mismatch", "expected pointer is not current")
			}
			if generation.GenerationID == pointer.CurrentGenerationID {
				return lifecycleFailure("promotion-noop", "evaluated generation is already current")
			}
			if generation.BaseGenerationID == nil || *generation.BaseGenerationID != pointer.CurrentGenerationID || *generation.BaseGenerationSHA256 != pointer.CurrentGenerationSHA256 {
				return lifecycleFailure("promotion-base-mismatch", "evaluated generation base is not the current generation")
			}
			priorIDValue := pointer.PointerID
			priorHashValue := digestBytes(pointerBytes)
			priorID, priorHash = &priorIDValue, &priorHashValue
		}
		if err := validateTransitionChronology(generation, pointer, config.TransitionedAt); err != nil {
			return err
		}
		core := RetrievalTransitionIntentCore{
			SchemaVersion: retrievalSchemaVersion, RecordKind: transitionIntentKind, Decision: "promoted",
			RollbackOfReceiptID: nil, TargetGenerationID: generation.GenerationID,
			TargetGenerationSHA256: config.GenerationHash, PriorPointerID: priorID, PriorPointerSHA256: priorHash,
			TransitionAssertions: promotionAssertions(pointer != nil),
			Authorization:        RetrievalTransitionAuthorization{Actor: config.Actor, Method: retrievalTransitionSignatureMethod, KeyID: config.KeyID, Namespace: retrievalTransitionSignatureNamespace, AllowedSignersSHA256: digestBytes(allowedSigners)},
			TransitionedAt:       config.TransitionedAt,
		}
		intent, err = sealTransitionIntent(core)
		return err
	})
	return intent, err
}

func PrepareGenerationRollback(config PrepareRollbackConfig) (RetrievalTransitionIntent, error) {
	var zero RetrievalTransitionIntent
	if lifecycleRequiredMissing(config.StoreRoot, config.StateRoot, config.AdmissionPolicyPath, config.AdmissionPolicyHash, config.AllowedSignersPath, config.Actor, config.KeyID, config.TransitionedAt, config.ExpectPointerID) {
		return zero, lifecycleFailure("rollback-input-invalid", "rollback preparation requires every pinned input and current pointer")
	}
	_, err := parseCanonicalUTC(config.TransitionedAt)
	if err != nil || config.ExpectPointerID == "" {
		return zero, lifecycleFailure("rollback-input-invalid", "rollback requires a canonical timestamp and expected pointer")
	}
	allowedSigners, err := readAndAuthorizeAllowedSigners(config.AllowedSignersPath, config.Actor, config.KeyID)
	if err != nil {
		return zero, lifecycleFailure("signer-not-authorized", err.Error())
	}
	var intent RetrievalTransitionIntent
	err = withGenerationLock(config.StateRoot, func() error {
		pointer, pointerBytes, err := validateCurrentGenerationState(config.StateRoot, config.StoreRoot, true)
		if err != nil {
			return err
		}
		if pointer.PointerID != config.ExpectPointerID {
			return lifecycleFailure("cas-mismatch", "expected pointer is not current")
		}
		if pointer.PreviousGenerationID == nil {
			return lifecycleFailure("rollback-target-missing", "current pointer has no previous generation")
		}
		target, _, err := loadStateGeneration(config.StateRoot, config.StoreRoot, *pointer.PreviousGenerationID, *pointer.PreviousGenerationSHA256)
		if err != nil {
			return err
		}
		if err := validateTransitionChronology(target, pointer, config.TransitionedAt); err != nil {
			return err
		}
		policy, _, err := loadCurrentAdmissionPolicy(config.AdmissionPolicyPath, config.AdmissionPolicyHash, config.TransitionedAt)
		if err != nil || !generationMatchesPolicy(target, policy, config.AdmissionPolicyHash) {
			return lifecycleFailure("admission-policy-invalid", "current admission policy is stale or does not bind the rollback target")
		}
		priorID, priorHash := pointer.PointerID, digestBytes(pointerBytes)
		rollbackOf := pointer.TransitionReceiptID
		core := RetrievalTransitionIntentCore{
			SchemaVersion: retrievalSchemaVersion, RecordKind: transitionIntentKind, Decision: "rolled_back",
			RollbackOfReceiptID: &rollbackOf, TargetGenerationID: target.GenerationID,
			TargetGenerationSHA256: *pointer.PreviousGenerationSHA256, PriorPointerID: &priorID, PriorPointerSHA256: &priorHash,
			TransitionAssertions: rollbackAssertions(),
			Authorization:        RetrievalTransitionAuthorization{Actor: config.Actor, Method: retrievalTransitionSignatureMethod, KeyID: config.KeyID, Namespace: retrievalTransitionSignatureNamespace, AllowedSignersSHA256: digestBytes(allowedSigners)},
			TransitionedAt:       config.TransitionedAt,
		}
		intent, err = sealTransitionIntent(core)
		return err
	})
	return intent, err
}

func ApplyGenerationTransition(config ApplyTransitionConfig) (ApplyTransitionResult, error) {
	var zero ApplyTransitionResult
	if lifecycleRequiredMissing(config.StoreRoot, config.StateRoot, config.IntentPath, config.IntentHash, config.SignaturePath, config.SignatureHash, config.AllowedSignersPath, config.AdmissionPolicyPath, config.AdmissionPolicyHash, config.ExpectedDecision) {
		return zero, lifecycleFailure("transition-input-invalid", "transition apply requires every pinned input and state root")
	}
	if config.ExpectedDecision != "promoted" && config.ExpectedDecision != "rolled_back" {
		return zero, lifecycleFailure("transition-decision-invalid", "expected decision is invalid")
	}
	intentBytes, err := readStableFile(config.IntentPath, "signed transition intent", maxPolicyBytes)
	if err != nil || !validSHA256(config.IntentHash) || digestBytes(intentBytes) != config.IntentHash {
		return zero, lifecycleFailure("intent-pin-mismatch", "signed transition intent does not match caller pin")
	}
	var intent RetrievalTransitionIntent
	if err := decodeStrictCanonical(intentBytes, &intent); err != nil || validateTransitionIntent(intent) != nil || intent.Decision != config.ExpectedDecision {
		return zero, lifecycleFailure("intent-invalid", "signed transition intent is invalid")
	}
	signature, err := readCanonicalSSHSIG(config.SignaturePath, config.SignatureHash)
	if err != nil {
		return zero, lifecycleFailure("signature-invalid", err.Error())
	}
	allowedSigners, err := readAndAuthorizeAllowedSigners(config.AllowedSignersPath, intent.Authorization.Actor, intent.Authorization.KeyID)
	if err != nil || digestBytes(allowedSigners) != intent.Authorization.AllowedSignersSHA256 {
		return zero, lifecycleFailure("authorization-policy-hash-mismatch", "allowed signers changed after intent preparation")
	}
	if err := verifyDetachedSSHSIG(intentBytes, signature, allowedSigners, intent.Authorization.Actor, intent.Authorization.KeyID, intent.Authorization.Namespace); err != nil {
		return zero, lifecycleFailure("signature-verification-failed", err.Error())
	}
	policy, _, err := loadCurrentAdmissionPolicy(config.AdmissionPolicyPath, config.AdmissionPolicyHash, intent.TransitionedAt)
	if err != nil {
		return zero, lifecycleFailure("admission-policy-invalid", "current admission policy is stale or invalid")
	}
	var promotionGeneration RetrievalGeneration
	var promotionBytes []byte
	if intent.Decision == "promoted" {
		if config.GenerationPath == "" || config.GenerationHash == "" {
			return zero, lifecycleFailure("candidate-missing", "promotion requires the exact evaluated generation")
		}
		promotionGeneration, promotionBytes, err = loadAndVerifyGeneration(config.GenerationPath, config.GenerationHash, config.StoreRoot)
		if err != nil || promotionGeneration.GenerationID != intent.TargetGenerationID || config.GenerationHash != intent.TargetGenerationSHA256 || !generationMatchesPolicy(promotionGeneration, policy, config.AdmissionPolicyHash) {
			return zero, lifecycleFailure("candidate-intent-mismatch", "evaluated generation differs from the signed intent or current policy")
		}
	} else if config.GenerationPath != "" || config.GenerationHash != "" {
		return zero, lifecycleFailure("candidate-unexpected", "rollback does not accept a generation input")
	}

	var result ApplyTransitionResult
	err = withGenerationLock(config.StateRoot, func() error {
		var prior *RetrievalGenerationPointer
		var priorBytes []byte
		if intent.PriorPointerID != nil {
			loaded, data, err := loadImmutablePointer(config.StateRoot, *intent.PriorPointerID, *intent.PriorPointerSHA256)
			if err != nil {
				return err
			}
			if err := verifyPointerChain(config.StateRoot, config.StoreRoot, loaded, digestBytes(data), map[string]bool{}, 0); err != nil {
				return err
			}
			prior, priorBytes = &loaded, data
		}
		var target RetrievalGeneration
		var targetBytes []byte
		if intent.Decision == "promoted" {
			target, targetBytes = promotionGeneration, promotionBytes
			if err := validatePromotionAgainstPrior(target, prior); err != nil {
				return err
			}
		} else {
			if prior == nil || prior.PreviousGenerationID == nil || intent.RollbackOfReceiptID == nil || intent.TargetGenerationID != *prior.PreviousGenerationID || intent.TargetGenerationSHA256 != *prior.PreviousGenerationSHA256 || *intent.RollbackOfReceiptID != prior.TransitionReceiptID {
				return lifecycleFailure("rollback-intent-invalid", "signed rollback no longer matches its exact prior pointer")
			}
			loaded, data, err := loadStateGeneration(config.StateRoot, config.StoreRoot, intent.TargetGenerationID, intent.TargetGenerationSHA256)
			if err != nil {
				return err
			}
			target, targetBytes = loaded, data
		}
		if !generationMatchesPolicy(target, policy, config.AdmissionPolicyHash) {
			return lifecycleFailure("admission-policy-invalid", "current admission policy does not bind the signed target")
		}
		if err := validateTransitionChronology(target, prior, intent.TransitionedAt); err != nil {
			return err
		}

		signatureRelative, _ := signatureStateRelative(config.SignatureHash)
		policyRelative, _ := policyStateRelative(digestBytes(allowedSigners))
		identity := RetrievalTransitionReceiptIdentity{
			SchemaVersion: retrievalSchemaVersion, RecordKind: transitionReceiptKind, Intent: intent,
			IntentDocumentSHA256: config.IntentHash, SignatureSHA256: config.SignatureHash,
			SignaturePath: signatureRelative, SignatureByteSize: int64(len(signature)),
			AllowedSignersSHA256: digestBytes(allowedSigners), AllowedSignersPath: policyRelative,
			AllowedSignersByteSize: int64(len(allowedSigners)),
		}
		receipt, err := sealTransitionReceipt(identity)
		if err != nil {
			return err
		}
		core := RetrievalGenerationPointerCore{
			SchemaVersion: retrievalSchemaVersion, RecordKind: generationPointerKind, Revision: 1,
			CurrentGenerationID: target.GenerationID, CurrentGenerationSHA256: intent.TargetGenerationSHA256,
			CurrentLexicalProfile: target.LexicalProfile, CurrentLexicalTokenizerID: target.LexicalTokenizerID,
			CurrentLexicalScorerID: target.LexicalScorerID,
			TransitionReceiptID:    receipt.ReceiptID, UpdatedAt: intent.TransitionedAt,
		}
		if prior != nil {
			core.Revision = prior.Revision + 1
			previousID, previousHash := prior.CurrentGenerationID, prior.CurrentGenerationSHA256
			core.PreviousGenerationID, core.PreviousGenerationSHA256 = &previousID, &previousHash
			if prior.CurrentLexicalProfile != "" {
				previousProfile, previousTokenizer, previousScorer := prior.CurrentLexicalProfile, prior.CurrentLexicalTokenizerID, prior.CurrentLexicalScorerID
				core.PreviousLexicalProfile, core.PreviousLexicalTokenizerID, core.PreviousLexicalScorerID = &previousProfile, &previousTokenizer, &previousScorer
			}
		}
		pointer, err := sealGenerationPointer(core)
		if err != nil {
			return err
		}
		pointerHash, pointerBytes, err := documentSHA256(pointer)
		if err != nil {
			return err
		}
		receipt.ResultingPointerID, receipt.ResultingPointerSHA256 = pointer.PointerID, pointerHash
		if err := validateTransitionReceipt(receipt); err != nil {
			return err
		}
		receiptBytes, err := marshalDocument(receipt)
		if err != nil {
			return err
		}

		alias, aliasBytes, err := readCurrentPointer(config.StateRoot, false)
		if err != nil {
			return err
		}
		if alias != nil && alias.PointerID == pointer.PointerID {
			if !bytesEqual(aliasBytes, pointerBytes) {
				return lifecycleFailure("pointer-conflict", "current pointer ID has different bytes")
			}
			if err := verifyPointerChain(config.StateRoot, config.StoreRoot, *alias, digestBytes(aliasBytes), map[string]bool{}, 0); err != nil {
				return err
			}
			result = ApplyTransitionResult{State: "ok", Idempotent: true, Decision: intent.Decision, Receipt: receipt, Pointer: pointer}
			return nil
		}
		if prior == nil {
			if alias != nil {
				return lifecycleFailure("cas-mismatch", "generation state is no longer empty")
			}
		} else if alias == nil || alias.PointerID != prior.PointerID || digestBytes(aliasBytes) != digestBytes(priorBytes) {
			return lifecycleFailure("cas-mismatch", "current pointer changed after intent preparation")
		}

		generationRelative, _ := generationStateRelative(target)
		if err := writeImmutableObject(config.StateRoot, generationRelative, targetBytes); err != nil {
			return lifecycleFailure("generation-persist-failed", err.Error())
		}
		if err := writeImmutableObject(config.StateRoot, signatureRelative, signature); err != nil {
			return lifecycleFailure("signature-persist-failed", err.Error())
		}
		if err := writeImmutableObject(config.StateRoot, policyRelative, allowedSigners); err != nil {
			return lifecycleFailure("policy-persist-failed", err.Error())
		}
		receiptRelative, _ := receiptStateRelative(receipt.ReceiptID)
		if err := writeImmutableObject(config.StateRoot, receiptRelative, receiptBytes); err != nil {
			return lifecycleFailure("receipt-persist-failed", err.Error())
		}
		if err := failLifecyclePoint(config.Failpoint, "after-receipt"); err != nil {
			return err
		}
		pointerRelative, _ := pointerStateRelative(pointer.PointerID)
		if err := writeImmutableObject(config.StateRoot, pointerRelative, pointerBytes); err != nil {
			return lifecycleFailure("pointer-persist-failed", err.Error())
		}
		if err := failLifecyclePoint(config.Failpoint, "after-pointer"); err != nil {
			return err
		}
		if err := failLifecyclePoint(config.Failpoint, "before-alias"); err != nil {
			return err
		}
		if err := writeAtomicPointerAlias(config.StateRoot, pointer); err != nil {
			return err
		}
		if err := failLifecyclePoint(config.Failpoint, "after-alias"); err != nil {
			return err
		}
		if err := verifyPointerChain(config.StateRoot, config.StoreRoot, pointer, pointerHash, map[string]bool{}, 0); err != nil {
			return err
		}
		result = ApplyTransitionResult{State: "ok", Idempotent: false, Decision: intent.Decision, Receipt: receipt, Pointer: pointer}
		return nil
	})
	return result, err
}

func generationMatchesPolicy(generation RetrievalGeneration, policy AdmissionPolicy, policyDocumentHash string) bool {
	return generation.AdmissionPolicyID == policy.PolicyID && generation.AdmissionPolicySHA256 == policyDocumentHash && generation.SnapshotManifestID == policy.SnapshotManifestID && generation.EvidenceManifestID == policy.EvidenceManifestID
}

func validateTransitionChronology(target RetrievalGeneration, prior *RetrievalGenerationPointer, transitionedAtText string) error {
	transitionedAt, err := parseCanonicalUTC(transitionedAtText)
	if err != nil {
		return lifecycleFailure("timestamp-invalid", "transition timestamp is not canonical UTC")
	}
	createdAt, err := parseCanonicalUTC(target.CreatedAt)
	if err != nil || createdAt.After(transitionedAt) {
		return lifecycleFailure("generation-time-invalid", "target generation was created after its transition")
	}
	if prior != nil {
		priorTime, err := parseCanonicalUTC(prior.UpdatedAt)
		if err != nil || !transitionedAt.After(priorTime) {
			return lifecycleFailure("timestamp-not-monotonic", "transition timestamp must advance")
		}
	}
	return nil
}

func validatePromotionAgainstPrior(target RetrievalGeneration, prior *RetrievalGenerationPointer) error {
	if prior == nil {
		if target.BaseGenerationID != nil {
			return lifecycleFailure("promotion-base-mismatch", "bootstrap target has a non-null base")
		}
		return nil
	}
	if target.BaseGenerationID == nil || *target.BaseGenerationID != prior.CurrentGenerationID || *target.BaseGenerationSHA256 != prior.CurrentGenerationSHA256 {
		return lifecycleFailure("promotion-base-mismatch", "promotion target base differs from current generation")
	}
	if target.GenerationID == prior.CurrentGenerationID {
		return lifecycleFailure("promotion-noop", "target generation is already current")
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func lifecycleRequiredMissing(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}
