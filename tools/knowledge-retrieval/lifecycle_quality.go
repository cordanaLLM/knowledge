package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	qualityReceiptKind               = "retrieval_quality_evaluator_receipt"
	qualityReceiptSignatureNamespace = "archeion-retrieval-quality-evaluation-v1"
	maxQualityReceiptBytes           = int64(1024 * 1024)
)

type verifiedQualityEvidence struct {
	receipt        RetrievalQualityReceipt
	receiptBytes   []byte
	signature      []byte
	allowedSigners []byte
}

func sealQualityReceipt(core RetrievalQualityReceiptCore) (RetrievalQualityReceipt, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return RetrievalQualityReceipt{}, err
	}
	digest := digestBytes(data)
	receipt := RetrievalQualityReceipt{ReceiptID: "retrieval-quality-receipt:" + digest, ReceiptPayloadSHA256: digest, RetrievalQualityReceiptCore: core}
	if err := validateQualityReceipt(receipt); err != nil {
		return RetrievalQualityReceipt{}, err
	}
	return receipt, nil
}

func validateQualityReceipt(receipt RetrievalQualityReceipt) error {
	coreBytes, err := json.Marshal(receipt.RetrievalQualityReceiptCore)
	if err != nil || receipt.ReceiptPayloadSHA256 != digestBytes(coreBytes) || receipt.ReceiptID != "retrieval-quality-receipt:"+receipt.ReceiptPayloadSHA256 {
		return errors.New("quality evaluator receipt identity mismatch")
	}
	if receipt.SchemaVersion != retrievalSchemaVersion || receipt.ReceiptKind != qualityReceiptKind || receipt.State != "passed" || !validPrefixedDigest(receipt.QualityReportID, "retrieval-quality-report:") || !validSHA256(receipt.QualityReportSHA256) || !validSHA256(receipt.EvaluatorExecutableSHA256) || !validSHA256(receipt.EvaluationRuntimeSHA256) {
		return errors.New("quality evaluator receipt contract invalid")
	}
	for name, value := range map[string]string{"evaluator": receipt.EvaluatorID, "evaluator-revision": receipt.EvaluatorRevision} {
		if !boundedMetadata(value) {
			return fmt.Errorf("quality evaluator receipt %s invalid", name)
		}
	}
	if _, err := parseCanonicalUTC(receipt.EvaluatedAt); err != nil {
		return err
	}
	authorization := receipt.Authorization
	if authorization.Method != retrievalTransitionSignatureMethod || authorization.Namespace != qualityReceiptSignatureNamespace || authorization.Actor == "" || strings.IndexFunc(authorization.Actor, func(r rune) bool { return r <= ' ' }) >= 0 || !sshFingerprintPattern.MatchString(authorization.KeyID) || !validSHA256(authorization.AllowedSignersSHA256) {
		return errors.New("quality evaluator receipt authorization invalid")
	}
	return nil
}

func loadAndVerifyQualityEvidence(config StageGenerationConfig, report RetrievalQualityReport) (verifiedQualityEvidence, error) {
	var zero verifiedQualityEvidence
	if lifecycleRequiredMissing(config.QualityReceiptPath, config.QualityReceiptHash, config.QualitySignaturePath, config.QualitySignatureHash, config.EvaluatorAllowedSignersPath) {
		return zero, errors.New("signed evaluator receipt, signature and trust policy are required")
	}
	receiptBytes, err := readStableFile(config.QualityReceiptPath, "quality evaluator receipt", maxQualityReceiptBytes)
	if err != nil || !validSHA256(config.QualityReceiptHash) || digestBytes(receiptBytes) != config.QualityReceiptHash {
		return zero, errors.New("quality evaluator receipt does not match caller pin")
	}
	var receipt RetrievalQualityReceipt
	if err := decodeStrictCanonical(receiptBytes, &receipt); err != nil || validateQualityReceipt(receipt) != nil {
		return zero, errors.New("quality evaluator receipt is invalid")
	}
	if receipt.QualityReportID != report.ReportID || receipt.QualityReportSHA256 != config.QualityReportHash || receipt.EvaluatorID != report.EvaluatorID || receipt.EvaluatorRevision != report.EvaluatorRevision || receipt.EvaluatorExecutableSHA256 != report.EvaluatorExecutableSHA256 || receipt.EvaluationRuntimeSHA256 != report.EvaluationRuntimeSHA256 || receipt.EvaluatedAt != report.EvaluatedAt {
		return zero, errors.New("quality evaluator receipt does not bind the exact report and evaluator")
	}
	allowedSigners, err := readAndAuthorizeAllowedSigners(config.EvaluatorAllowedSignersPath, receipt.Authorization.Actor, receipt.Authorization.KeyID)
	if err != nil || digestBytes(allowedSigners) != receipt.Authorization.AllowedSignersSHA256 {
		return zero, errors.New("quality evaluator allowed_signers does not match the signed receipt")
	}
	signature, err := readCanonicalSSHSIG(config.QualitySignaturePath, config.QualitySignatureHash)
	if err != nil {
		return zero, fmt.Errorf("quality evaluator signature: %w", err)
	}
	if err := verifyDetachedSSHSIG(receiptBytes, signature, allowedSigners, receipt.Authorization.Actor, receipt.Authorization.KeyID, receipt.Authorization.Namespace); err != nil {
		return zero, fmt.Errorf("quality evaluator signature verification failed: %w", err)
	}
	return verifiedQualityEvidence{receipt: receipt, receiptBytes: receiptBytes, signature: signature, allowedSigners: allowedSigners}, nil
}

func verifyStoredQualityEvidence(storeRoot string, generation RetrievalGeneration, report RetrievalQualityReport) error {
	receiptBytes, _, err := readBoundStoreDocument(storeRoot, generation.QualityReceiptPath, generation.QualityReceiptSHA256, generation.QualityReceiptByteSize, maxQualityReceiptBytes)
	if err != nil {
		return errors.New("generation quality evaluator receipt is unavailable")
	}
	var receipt RetrievalQualityReceipt
	if err := decodeStrictCanonical(receiptBytes, &receipt); err != nil || validateQualityReceipt(receipt) != nil {
		return errors.New("generation quality evaluator receipt is invalid")
	}
	if receipt.ReceiptID != generation.QualityReceiptID || receipt.QualityReportID != report.ReportID || receipt.QualityReportSHA256 != generation.QualityReportSHA256 || receipt.EvaluatorID != generation.EvaluatorID || receipt.EvaluatorRevision != generation.EvaluatorRevision || receipt.EvaluatorExecutableSHA256 != generation.EvaluatorExecutableSHA256 || receipt.EvaluationRuntimeSHA256 != generation.EvaluationRuntimeSHA256 || receipt.EvaluatedAt != report.EvaluatedAt || receipt.Authorization.Actor != generation.EvaluatorActor || receipt.Authorization.KeyID != generation.EvaluatorKeyID || receipt.Authorization.Namespace != generation.EvaluatorSignatureNamespace || receipt.Authorization.AllowedSignersSHA256 != generation.EvaluatorAllowedSignersSHA256 {
		return errors.New("generation quality evaluator lineage differs")
	}
	signature, _, err := readBoundStoreDocument(storeRoot, generation.QualitySignaturePath, generation.QualitySignatureSHA256, generation.QualitySignatureByteSize, maxSignatureBytes)
	if err != nil || validateCanonicalSSHSIG(signature) != nil {
		return errors.New("generation quality evaluator signature is unavailable")
	}
	allowedSigners, _, err := readBoundStoreDocument(storeRoot, generation.EvaluatorAllowedSignersPath, generation.EvaluatorAllowedSignersSHA256, generation.EvaluatorAllowedSignersByteSize, maxAllowedSignersBytes)
	if err != nil {
		return errors.New("generation evaluator allowed_signers is unavailable")
	}
	if _, err := readAndAuthorizeAllowedSignersBytes(allowedSigners, receipt.Authorization.Actor, receipt.Authorization.KeyID); err != nil {
		return errors.New("generation evaluator is not authorized by its exact trust policy")
	}
	if err := verifyDetachedSSHSIG(receiptBytes, signature, allowedSigners, receipt.Authorization.Actor, receipt.Authorization.KeyID, receipt.Authorization.Namespace); err != nil {
		return errors.New("generation quality evaluator signature verification failed")
	}
	return nil
}
