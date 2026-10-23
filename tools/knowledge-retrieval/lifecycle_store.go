package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	transitionIntentKind  = "retrieval_generation_transition_intent"
	transitionReceiptKind = "retrieval_generation_transition_receipt"
	generationPointerKind = "retrieval_generation_pointer"
	generationAliasPath   = "generation-pointer.json"
	generationLockPath    = ".generation.lock"
	maxLifecycleDepth     = 10_000
)

func lifecycleFailure(code, message string) error {
	return &LifecycleError{Code: code, Message: message}
}

func lifecycleCode(err error) string {
	var lifecycle *LifecycleError
	if errors.As(err, &lifecycle) {
		return lifecycle.Code
	}
	return "backend-io-error"
}

func generationStateRelative(generation RetrievalGeneration) (string, error) {
	return contentObjectPath("generations", generation.GenerationPayloadSHA256)
}

func pointerStateRelative(pointerID string) (string, error) {
	if !validPrefixedDigest(pointerID, "retrieval-pointer:") {
		return "", errors.New("pointer ID invalid")
	}
	return contentObjectPath("pointers", strings.TrimPrefix(pointerID, "retrieval-pointer:"))
}

func receiptStateRelative(receiptID string) (string, error) {
	if !validPrefixedDigest(receiptID, "retrieval-receipt:") {
		return "", errors.New("receipt ID invalid")
	}
	return contentObjectPath("receipts", strings.TrimPrefix(receiptID, "retrieval-receipt:"))
}

func signatureStateRelative(signatureHash string) (string, error) {
	return contentBinaryPath("signatures", signatureHash, ".sshsig")
}

func policyStateRelative(policyHash string) (string, error) {
	return contentBinaryPath("allowed-signers", policyHash, ".allowed_signers")
}

func withGenerationLock(stateRoot string, operation func() error) error {
	if strings.TrimSpace(stateRoot) == "" {
		return lifecycleFailure("state-root-invalid", "generation state root is required")
	}
	abs, err := filepath.Abs(stateRoot)
	if err != nil || validateNoSymlinkExistingPrefix(abs) != nil {
		return lifecycleFailure("state-root-invalid", "generation state root is unavailable")
	}
	root, rootInfo, err := openSafeOutputRoot(abs)
	if err != nil {
		return lifecycleFailure("state-root-invalid", "generation state root is unavailable")
	}
	defer root.Close()
	if info, err := root.Lstat(generationLockPath); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return lifecycleFailure("lock-invalid", "generation state lock is not a regular non-symlink file")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return lifecycleFailure("lock-unavailable", "generation state lock cannot be inspected")
	}
	lock, err := root.OpenFile(generationLockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return lifecycleFailure("lock-unavailable", "generation state lock is unavailable")
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	boundInfo, boundErr := root.Lstat(generationLockPath)
	if err != nil || boundErr != nil || boundInfo.Mode()&os.ModeSymlink != 0 || !lockInfo.Mode().IsRegular() || !os.SameFile(lockInfo, boundInfo) {
		return lifecycleFailure("lock-invalid", "generation state lock is not a regular file")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return lifecycleFailure("lock-unavailable", "generation state lock cannot be acquired")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := verifyRootStillBound(abs, root, rootInfo); err != nil {
		return lifecycleFailure("state-root-changed", "generation state root changed while locked")
	}
	if err := operation(); err != nil {
		return err
	}
	if err := verifyRootStillBound(abs, root, rootInfo); err != nil {
		return lifecycleFailure("state-root-changed", "generation state root changed while locked")
	}
	return nil
}

func readCurrentPointer(stateRoot string, required bool) (*RetrievalGenerationPointer, []byte, error) {
	alias := filepath.Join(stateRoot, generationAliasPath)
	if _, err := os.Lstat(alias); errors.Is(err, fs.ErrNotExist) {
		if required {
			return nil, nil, lifecycleFailure("pointer-missing", "no current retrieval generation pointer exists")
		}
		return nil, nil, nil
	}
	data, err := readStableFile(alias, "generation pointer alias", maxPolicyBytes)
	if err != nil {
		return nil, nil, lifecycleFailure("pointer-unavailable", "generation pointer alias is unavailable")
	}
	var pointer RetrievalGenerationPointer
	if err := decodeStrictCanonical(data, &pointer); err != nil || validateGenerationPointer(pointer) != nil {
		return nil, nil, lifecycleFailure("pointer-invalid", "generation pointer alias is invalid")
	}
	return &pointer, data, nil
}

func loadImmutablePointer(stateRoot, pointerID, expectedHash string) (RetrievalGenerationPointer, []byte, error) {
	var zero RetrievalGenerationPointer
	relative, err := pointerStateRelative(pointerID)
	if err != nil || !validSHA256(expectedHash) {
		return zero, nil, lifecycleFailure("pointer-binding-invalid", "pointer binding is invalid")
	}
	data, err := readStableFile(filepath.Join(stateRoot, filepath.FromSlash(relative)), "immutable generation pointer", maxPolicyBytes)
	if err != nil || digestBytes(data) != expectedHash {
		return zero, nil, lifecycleFailure("pointer-unavailable", "immutable generation pointer is unavailable")
	}
	var pointer RetrievalGenerationPointer
	if err := decodeStrictCanonical(data, &pointer); err != nil || validateGenerationPointer(pointer) != nil || pointer.PointerID != pointerID {
		return zero, nil, lifecycleFailure("pointer-invalid", "immutable generation pointer is invalid")
	}
	return pointer, data, nil
}

func loadImmutableReceipt(stateRoot, receiptID string) (RetrievalTransitionReceipt, []byte, error) {
	var zero RetrievalTransitionReceipt
	relative, err := receiptStateRelative(receiptID)
	if err != nil {
		return zero, nil, lifecycleFailure("receipt-binding-invalid", "transition receipt binding is invalid")
	}
	data, err := readStableFile(filepath.Join(stateRoot, filepath.FromSlash(relative)), "immutable transition receipt", maxPolicyBytes)
	if err != nil {
		return zero, nil, lifecycleFailure("receipt-unavailable", "transition receipt is unavailable")
	}
	var receipt RetrievalTransitionReceipt
	if err := decodeStrictCanonical(data, &receipt); err != nil || validateTransitionReceipt(receipt) != nil || receipt.ReceiptID != receiptID {
		return zero, nil, lifecycleFailure("receipt-invalid", "transition receipt is invalid")
	}
	return receipt, data, nil
}

func loadStateGeneration(stateRoot, storeRoot, generationID, expectedHash string) (RetrievalGeneration, []byte, error) {
	var zero RetrievalGeneration
	if !validPrefixedDigest(generationID, "retrieval-generation:") || !validSHA256(expectedHash) {
		return zero, nil, lifecycleFailure("generation-binding-invalid", "generation binding is invalid")
	}
	relative, err := contentObjectPath("generations", strings.TrimPrefix(generationID, "retrieval-generation:"))
	if err != nil {
		return zero, nil, lifecycleFailure("generation-binding-invalid", "generation binding is invalid")
	}
	generation, data, err := loadAndVerifyGeneration(filepath.Join(stateRoot, filepath.FromSlash(relative)), expectedHash, storeRoot)
	if err != nil || generation.GenerationID != generationID {
		return zero, nil, lifecycleFailure("generation-unavailable", "whole retrieval generation verification failed")
	}
	return generation, data, nil
}

func writeAtomicPointerAlias(stateRoot string, pointer RetrievalGenerationPointer) error {
	data, err := marshalDocument(pointer)
	if err != nil {
		return err
	}
	root, rootInfo, err := openSafeOutputRoot(stateRoot)
	if err != nil {
		return lifecycleFailure("state-root-invalid", "generation state root is unavailable")
	}
	defer root.Close()
	if info, err := root.Lstat(generationAliasPath); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return lifecycleFailure("pointer-alias-invalid", "generation pointer alias is not a regular file")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return lifecycleFailure("pointer-alias-unavailable", "generation pointer alias cannot be inspected")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := ".generation-pointer-" + hex.EncodeToString(random) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return lifecycleFailure("pointer-alias-write-failed", "cannot stage generation pointer alias")
	}
	defer root.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		return closeWithError(lifecycleFailure("pointer-alias-write-failed", "cannot write generation pointer alias"), file)
	}
	if err := file.Sync(); err != nil {
		return closeWithError(lifecycleFailure("pointer-alias-write-failed", "cannot sync generation pointer alias"), file)
	}
	if err := file.Close(); err != nil {
		return lifecycleFailure("pointer-alias-write-failed", "cannot close generation pointer alias")
	}
	if staged, err := readRootStableFile(root, temporary, int64(len(data))); err != nil || !bytes.Equal(staged, data) {
		return lifecycleFailure("pointer-alias-write-failed", "staged generation pointer alias changed")
	}
	if err := verifyRootStillBound(stateRoot, root, rootInfo); err != nil {
		return lifecycleFailure("state-root-changed", "generation state root changed before pointer exchange")
	}
	if err := root.Rename(temporary, generationAliasPath); err != nil {
		return lifecycleFailure("pointer-alias-write-failed", "atomic generation pointer exchange failed")
	}
	if err := syncRootDirectory(root, "."); err != nil {
		return lifecycleFailure("pointer-alias-write-failed", "generation pointer directory sync failed")
	}
	committed, err := readRootStableFile(root, generationAliasPath, int64(len(data)))
	if err != nil || !bytes.Equal(committed, data) {
		return lifecycleFailure("pointer-alias-write-failed", "generation pointer alias post-check failed")
	}
	return nil
}

func sealTransitionIntent(core RetrievalTransitionIntentCore) (RetrievalTransitionIntent, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return RetrievalTransitionIntent{}, err
	}
	digest := digestBytes(data)
	result := RetrievalTransitionIntent{IntentID: "retrieval-intent:" + digest, IntentPayloadSHA256: digest, RetrievalTransitionIntentCore: core}
	if err := validateTransitionIntent(result); err != nil {
		return RetrievalTransitionIntent{}, err
	}
	return result, nil
}

func validateTransitionIntent(intent RetrievalTransitionIntent) error {
	data, err := json.Marshal(intent.RetrievalTransitionIntentCore)
	if err != nil || intent.IntentPayloadSHA256 != digestBytes(data) || intent.IntentID != "retrieval-intent:"+intent.IntentPayloadSHA256 {
		return errors.New("transition intent identity mismatch")
	}
	if intent.SchemaVersion != retrievalSchemaVersion || intent.RecordKind != transitionIntentKind || (intent.Decision != "promoted" && intent.Decision != "rolled_back") || !validPrefixedDigest(intent.TargetGenerationID, "retrieval-generation:") || !validSHA256(intent.TargetGenerationSHA256) {
		return errors.New("transition intent contract invalid")
	}
	if _, err := parseCanonicalUTC(intent.TransitionedAt); err != nil {
		return err
	}
	if (intent.PriorPointerID == nil) != (intent.PriorPointerSHA256 == nil) || (intent.PriorPointerID != nil && (!validPrefixedDigest(*intent.PriorPointerID, "retrieval-pointer:") || !validSHA256(*intent.PriorPointerSHA256))) {
		return errors.New("transition intent prior binding invalid")
	}
	auth := intent.Authorization
	if auth.Method != retrievalTransitionSignatureMethod || auth.Namespace != retrievalTransitionSignatureNamespace || auth.Actor == "" || strings.IndexFunc(auth.Actor, func(r rune) bool { return r <= ' ' }) >= 0 || !sshFingerprintPattern.MatchString(auth.KeyID) || !validSHA256(auth.AllowedSignersSHA256) {
		return errors.New("transition authorization invalid")
	}
	if intent.Decision == "promoted" {
		if intent.RollbackOfReceiptID != nil || intent.TransitionAssertions != promotionAssertions(intent.PriorPointerID != nil) {
			return errors.New("promotion intent assertions invalid")
		}
	} else {
		if intent.PriorPointerID == nil || intent.RollbackOfReceiptID == nil || !validPrefixedDigest(*intent.RollbackOfReceiptID, "retrieval-receipt:") || intent.TransitionAssertions != rollbackAssertions() {
			return errors.New("rollback intent assertions invalid")
		}
	}
	return nil
}

func promotionAssertions(hasPrior bool) RetrievalTransitionAssertions {
	return RetrievalTransitionAssertions{true, true, true, true, true, hasPrior, false}
}

func rollbackAssertions() RetrievalTransitionAssertions {
	return RetrievalTransitionAssertions{true, true, true, true, true, true, true}
}

func sealTransitionReceipt(identity RetrievalTransitionReceiptIdentity) (RetrievalTransitionReceipt, error) {
	data, err := json.Marshal(identity)
	if err != nil {
		return RetrievalTransitionReceipt{}, err
	}
	digest := digestBytes(data)
	return RetrievalTransitionReceipt{ReceiptID: "retrieval-receipt:" + digest, ReceiptPayloadSHA256: digest, RetrievalTransitionReceiptIdentity: identity}, nil
}

func validateTransitionReceipt(receipt RetrievalTransitionReceipt) error {
	data, err := json.Marshal(receipt.RetrievalTransitionReceiptIdentity)
	if err != nil || receipt.ReceiptPayloadSHA256 != digestBytes(data) || receipt.ReceiptID != "retrieval-receipt:"+receipt.ReceiptPayloadSHA256 {
		return errors.New("transition receipt identity mismatch")
	}
	if receipt.SchemaVersion != retrievalSchemaVersion || receipt.RecordKind != transitionReceiptKind || validateTransitionIntent(receipt.Intent) != nil || !validSHA256(receipt.IntentDocumentSHA256) || !validSHA256(receipt.SignatureSHA256) || !validSHA256(receipt.AllowedSignersSHA256) || receipt.SignatureByteSize < 1 || receipt.SignatureByteSize > maxSignatureBytes || receipt.AllowedSignersByteSize < 1 || receipt.AllowedSignersByteSize > maxAllowedSignersBytes || validateRelativePath(receipt.SignaturePath) != nil || validateRelativePath(receipt.AllowedSignersPath) != nil || !validPrefixedDigest(receipt.ResultingPointerID, "retrieval-pointer:") || !validSHA256(receipt.ResultingPointerSHA256) {
		return errors.New("transition receipt contract invalid")
	}
	return nil
}

func sealGenerationPointer(core RetrievalGenerationPointerCore) (RetrievalGenerationPointer, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return RetrievalGenerationPointer{}, err
	}
	digest := digestBytes(data)
	result := RetrievalGenerationPointer{PointerID: "retrieval-pointer:" + digest, PointerPayloadSHA256: digest, RetrievalGenerationPointerCore: core}
	if err := validateGenerationPointer(result); err != nil {
		return RetrievalGenerationPointer{}, err
	}
	return result, nil
}

func validateGenerationPointer(pointer RetrievalGenerationPointer) error {
	data, err := json.Marshal(pointer.RetrievalGenerationPointerCore)
	if err != nil || pointer.PointerPayloadSHA256 != digestBytes(data) || pointer.PointerID != "retrieval-pointer:"+pointer.PointerPayloadSHA256 {
		return errors.New("generation pointer identity mismatch")
	}
	if pointer.SchemaVersion != retrievalSchemaVersion || pointer.RecordKind != generationPointerKind || pointer.Revision < 1 || !validPrefixedDigest(pointer.CurrentGenerationID, "retrieval-generation:") || !validSHA256(pointer.CurrentGenerationSHA256) || !validPrefixedDigest(pointer.TransitionReceiptID, "retrieval-receipt:") {
		return errors.New("generation pointer contract invalid")
	}
	if _, err := parseCanonicalUTC(pointer.UpdatedAt); err != nil {
		return err
	}
	if (pointer.PreviousGenerationID == nil) != (pointer.PreviousGenerationSHA256 == nil) || (pointer.PreviousGenerationID != nil && (!validPrefixedDigest(*pointer.PreviousGenerationID, "retrieval-generation:") || !validSHA256(*pointer.PreviousGenerationSHA256))) {
		return errors.New("generation pointer previous binding invalid")
	}
	if pointer.CurrentLexicalProfile == "" {
		if pointer.CurrentLexicalTokenizerID != "" || pointer.CurrentLexicalScorerID != "" {
			return errors.New("legacy current pointer carries successor lexical lineage")
		}
	} else if !validBM25FLineage(pointer.CurrentLexicalProfile, pointer.CurrentLexicalTokenizerID, pointer.CurrentLexicalScorerID) {
		return errors.New("current pointer lexical profile binding invalid")
	}
	previousLineageNil := pointer.PreviousLexicalProfile == nil && pointer.PreviousLexicalTokenizerID == nil && pointer.PreviousLexicalScorerID == nil
	previousLineageComplete := pointer.PreviousLexicalProfile != nil && pointer.PreviousLexicalTokenizerID != nil && pointer.PreviousLexicalScorerID != nil
	if !previousLineageNil && !previousLineageComplete {
		return errors.New("previous pointer lexical profile binding is partial")
	}
	if pointer.PreviousGenerationID == nil && !previousLineageNil {
		return errors.New("bootstrap pointer carries previous lexical lineage")
	}
	if previousLineageComplete && !validBM25FLineage(*pointer.PreviousLexicalProfile, *pointer.PreviousLexicalTokenizerID, *pointer.PreviousLexicalScorerID) {
		return errors.New("previous pointer lexical profile binding invalid")
	}
	return nil
}

func documentSHA256(value any) (string, []byte, error) {
	data, err := marshalDocument(value)
	if err != nil {
		return "", nil, err
	}
	return digestBytes(data), data, nil
}

func immutableStatePath(stateRoot, relative string) string {
	return filepath.Join(stateRoot, filepath.FromSlash(path.Clean(relative)))
}

func failLifecyclePoint(requested, name string) error {
	if requested == name {
		return lifecycleFailure("injected-crash", fmt.Sprintf("injected crash at %s", name))
	}
	return nil
}
