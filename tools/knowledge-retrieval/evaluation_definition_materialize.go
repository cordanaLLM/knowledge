package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// MaterializeExpandedEvaluationDefinition seals one strict canonical core as
// an immutable, content-derived definition. It grants no evaluation, source,
// serving or release authority.
func MaterializeExpandedEvaluationDefinition(corePath, storeRoot string) (RetrievalExpandedEvaluationDefinition, string, error) {
	var zero RetrievalExpandedEvaluationDefinition
	if strings.TrimSpace(corePath) == "" || strings.TrimSpace(storeRoot) == "" {
		return zero, "", errors.New("expanded evaluation definition core path and store are required")
	}
	coreBytes, err := readStableFile(corePath, "expanded evaluation definition core", maxEvaluationDefinitionBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read expanded evaluation definition core: %w", err)
	}
	var core RetrievalExpandedEvaluationDefinitionCore
	if err := decodeStrictCanonical(coreBytes, &core); err != nil {
		return zero, "", fmt.Errorf("decode expanded evaluation definition core: %w", err)
	}
	definition, err := sealExpandedEvaluationDefinition(core)
	if err != nil {
		return zero, "", fmt.Errorf("seal expanded evaluation definition: %w", err)
	}
	data, err := marshalDocument(definition)
	if err != nil {
		return zero, "", err
	}
	// Replay the sealed wire document through the same strict decoder before
	// committing it. This protects the v1 singular/blocked compatibility path
	// and the v2/v3 per-lane binding shapes from diverging at materialization.
	var replayed RetrievalExpandedEvaluationDefinition
	if err := decodeStrictCanonical(data, &replayed); err != nil {
		return zero, "", fmt.Errorf("decode replayed expanded evaluation definition: %w", err)
	}
	if err := validateExpandedEvaluationDefinition(replayed); err != nil {
		return zero, "", fmt.Errorf("validate replayed expanded evaluation definition: %w", err)
	}
	if replayed.DefinitionID != definition.DefinitionID {
		return zero, "", errors.New("replayed expanded evaluation definition identity mismatch")
	}
	relative, err := contentObjectPath("evaluation-definitions", definition.DefinitionPayloadSHA256)
	if err != nil {
		return zero, "", err
	}
	root, err := filepath.Abs(storeRoot)
	if err != nil || validateNoSymlinkExistingPrefix(root) != nil {
		return zero, "", errors.New("expanded evaluation definition store is unavailable")
	}
	if err := writeImmutableObject(root, relative, data); err != nil {
		return zero, "", fmt.Errorf("commit expanded evaluation definition: %w", err)
	}
	return definition, filepath.Join(root, filepath.FromSlash(relative)), nil
}
