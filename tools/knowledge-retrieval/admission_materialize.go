package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// MaterializeAdmissionPolicy derives an admission policy's immutable identity
// from a strict canonical core document. It grants no review or promotion
// authority; callers must separately bind the materialized policy to the exact
// snapshot and evidence manifests that they admit.
func MaterializeAdmissionPolicy(corePath, storeRoot string) (AdmissionPolicy, string, error) {
	var zero AdmissionPolicy
	if strings.TrimSpace(corePath) == "" {
		return zero, "", errors.New("admission policy core path is required")
	}
	if strings.TrimSpace(storeRoot) == "" {
		return zero, "", errors.New("admission policy store is required")
	}

	coreBytes, err := readStableFile(corePath, "admission policy core", maxPolicyBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read admission policy core: %w", err)
	}
	var core AdmissionPolicyCore
	if err := decodeStrictCanonical(coreBytes, &core); err != nil {
		return zero, "", fmt.Errorf("decode admission policy core: %w", err)
	}

	policy, err := deriveAdmissionPolicy(core)
	if err != nil {
		return zero, "", fmt.Errorf("derive admission policy identity: %w", err)
	}
	if err := validateMaterializedAdmissionPolicy(policy); err != nil {
		return zero, "", fmt.Errorf("admission policy core is invalid: %w", err)
	}
	policyBytes, err := marshalDocument(policy)
	if err != nil {
		return zero, "", fmt.Errorf("encode admission policy: %w", err)
	}
	relative, err := contentObjectPath("admission-policies", policy.PolicyPayloadSHA256)
	if err != nil {
		return zero, "", fmt.Errorf("derive admission policy CAS path: %w", err)
	}
	absoluteStore, err := filepath.Abs(storeRoot)
	if err != nil {
		return zero, "", fmt.Errorf("resolve admission policy store: %w", err)
	}
	if err := writeImmutableObject(absoluteStore, relative, policyBytes); err != nil {
		return zero, "", fmt.Errorf("commit admission policy: %w", err)
	}
	return policy, filepath.Join(absoluteStore, filepath.FromSlash(relative)), nil
}

func deriveAdmissionPolicy(core AdmissionPolicyCore) (AdmissionPolicy, error) {
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return AdmissionPolicy{}, err
	}
	digest := digestBytes(coreBytes)
	return AdmissionPolicy{
		PolicyID:            "retrieval-admission:" + digest,
		PolicyPayloadSHA256: digest,
		AdmissionPolicyCore: core,
	}, nil
}

func validateMaterializedAdmissionPolicy(policy AdmissionPolicy) error {
	if err := validatePolicyIdentity(policy); err != nil {
		return err
	}
	if policy.State != "active" {
		return errors.New("policy state must be active")
	}
	if !validPrefixedDigest(policy.SnapshotManifestID, "snapshot-manifest:") {
		return errors.New("snapshot manifest identity is invalid")
	}
	if !validPrefixedDigest(policy.EvidenceManifestID, "evidence-manifest:") {
		return errors.New("evidence manifest identity is invalid")
	}
	for name, value := range map[string]string{
		"snapshot_id":          policy.SnapshotID,
		"source_id":            policy.SourceID,
		"component_id":         policy.ComponentID,
		"component_version_id": policy.ComponentVersionID,
	} {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("%s is empty or non-canonical", name)
		}
	}
	if policy.AccessScope != "public" || !policy.RetrievalAllowed {
		return errors.New("policy must explicitly authorize public retrieval")
	}
	if policy.SourceState != "present" {
		return errors.New("source state must be present")
	}
	if policy.DeletionState != "active" {
		return errors.New("deletion state must be active")
	}
	if policy.Tombstone {
		return errors.New("tombstoned sources cannot be materialized as active admission")
	}
	return nil
}
