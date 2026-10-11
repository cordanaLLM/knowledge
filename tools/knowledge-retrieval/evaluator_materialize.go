package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// MaterializeEvaluationSuite converts a strict canonical suite core into one
// immutable, content-derived frozen suite. The self-referential suite identity
// is never supplied by a caller.
func MaterializeEvaluationSuite(corePath, storeRoot string) (RetrievalEvaluationSuite, string, error) {
	var zero RetrievalEvaluationSuite
	if strings.TrimSpace(corePath) == "" || strings.TrimSpace(storeRoot) == "" {
		return zero, "", errors.New("evaluation suite core path and store are required")
	}
	coreBytes, err := readStableFile(corePath, "evaluation suite core", maxEvaluationSuiteBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read evaluation suite core: %w", err)
	}
	var core RetrievalEvaluationSuiteCore
	if err := decodeStrictCanonical(coreBytes, &core); err != nil {
		return zero, "", fmt.Errorf("decode evaluation suite core: %w", err)
	}
	suite, err := sealEvaluationSuite(core)
	if err != nil {
		return zero, "", fmt.Errorf("seal evaluation suite: %w", err)
	}
	data, err := marshalDocument(suite)
	if err != nil {
		return zero, "", err
	}
	relative, err := contentObjectPath("evaluation-suites", suite.SuitePayloadSHA256)
	if err != nil {
		return zero, "", err
	}
	root, err := filepath.Abs(storeRoot)
	if err != nil || validateNoSymlinkExistingPrefix(root) != nil {
		return zero, "", errors.New("evaluation suite store is unavailable")
	}
	if err := writeImmutableObject(root, relative, data); err != nil {
		return zero, "", fmt.Errorf("commit evaluation suite: %w", err)
	}
	return suite, filepath.Join(root, filepath.FromSlash(relative)), nil
}
