package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	maxRegistryStringBytes         = 64 << 10
	maxRegistryToolRowBytes        = 8 << 10
	maxRegistryRecordBytes         = 1 << 20
	maxRegistryTopObjectBytes      = 4 << 20
	maxRegistryReconciliationBytes = 64 << 20
	maxRegistryValueDepth          = 32
	maxRegistryRecordNodes         = 32_768
	maxRegistryTopObjectNodes      = 200_000
	maxRegistryReconciliationNodes = 2_000_000
	maxRegistryCollectionEntries   = 4_096
	maxRegistryTopCollection       = 200_000
	maxRegistryComponents          = 100_000
	maxRegistrySources             = 100_000
	maxRegistryVersions            = 200_000
	maxRegistryOccurrences         = 400_000
	// Widest known producer envelope (MANIFEST_BOUNDS_V3). V1/V2 declare 400_000;
	// their own bounds block is what pins them, this is the resource guard.
	maxRegistryEdges                = 700_000
	maxRegistryGaps                 = 400_000
	maxRegistryGapTypes             = 1_024
	maxRegistryGapTypeBytes         = 128
	maxRegistryStatusGapTypes       = 256
	maxRegistryCountKeys            = 6
	maxRegistryCountKeyBytes        = 64
	maxRegistryChannelsPerComponent = 64
	maxRegistryLifecycles           = 64
	maxRegistryEvidenceItems        = 4_096
	maxRegistryReconciliationItems  = 100_000
	maxRegistryChangeInputBytes     = 8 << 10
	maxRegistryChangeCanonicalBytes = 64 << 10
)

var registryCountKeys = map[string]struct{}{
	"sources": {}, "components": {}, "versions": {}, "occurrences": {},
	"dependency_edges": {}, "gaps": {},
}

const projectionLegacyResolutionCount = "official_resolution_runs"

var reconciliationKeys = []string{
	"added", "changed", "complete_mark", "missing", "previous_manifest_id",
	"removal_allowed", "removed",
}

type manifestValueBudget struct {
	bytes      int
	nodes      int
	maxBytes   int
	maxNodes   int
	maxEntries int
}

func newManifestValueBudget(maxBytes, maxNodes, maxEntries int) *manifestValueBudget {
	return &manifestValueBudget{maxBytes: maxBytes, maxNodes: maxNodes, maxEntries: maxEntries}
}

func (budget *manifestValueBudget) consumeString(value string) error {
	if len(value) > maxRegistryStringBytes {
		return fmt.Errorf("string exceeds %d-byte bound", maxRegistryStringBytes)
	}
	budget.bytes += len(value)
	if budget.bytes > budget.maxBytes {
		return fmt.Errorf("value exceeds %d-byte aggregate bound", budget.maxBytes)
	}
	return nil
}

func (budget *manifestValueBudget) consumeNode() error {
	budget.nodes++
	if budget.nodes > budget.maxNodes {
		return fmt.Errorf("value exceeds %d-node bound", budget.maxNodes)
	}
	return nil
}

func (budget *manifestValueBudget) walk(value any, depth int) error {
	if depth > maxRegistryValueDepth {
		return fmt.Errorf("value exceeds %d-level depth bound", maxRegistryValueDepth)
	}
	if err := budget.consumeNode(); err != nil {
		return err
	}
	switch typed := value.(type) {
	case nil, bool, float32, float64, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return nil
	case json.Number:
		return budget.consumeString(typed.String())
	case string:
		return budget.consumeString(typed)
	case []string:
		if len(typed) > budget.maxEntries {
			return fmt.Errorf("collection exceeds %d-entry bound", budget.maxEntries)
		}
		for _, item := range typed {
			if err := budget.walk(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []any:
		if len(typed) > budget.maxEntries {
			return fmt.Errorf("collection exceeds %d-entry bound", budget.maxEntries)
		}
		for _, item := range typed {
			if err := budget.walk(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []map[string]any:
		if len(typed) > budget.maxEntries {
			return fmt.Errorf("collection exceeds %d-entry bound", budget.maxEntries)
		}
		for _, item := range typed {
			if err := budget.walk(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if len(typed) > budget.maxEntries {
			return fmt.Errorf("object exceeds %d-field bound", budget.maxEntries)
		}
		for key, item := range typed {
			if err := budget.consumeString(key); err != nil {
				return err
			}
			if err := budget.walk(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]string:
		if len(typed) > budget.maxEntries {
			return fmt.Errorf("object exceeds %d-field bound", budget.maxEntries)
		}
		for key, item := range typed {
			if err := budget.consumeString(key); err != nil {
				return err
			}
			if err := budget.walk(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported decoded JSON value type %T", value)
	}
}

func validateLooseValue(label string, value any, maximum, nodes, entries int) error {
	budget := newManifestValueBudget(maximum, nodes, entries)
	if err := budget.walk(value, 0); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func validateExposedRow(label string, values ...string) error {
	budget := newManifestValueBudget(maxRegistryToolRowBytes, maxRegistryRecordNodes, maxRegistryCollectionEntries)
	for _, value := range values {
		if err := budget.walk(value, 0); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	return nil
}

func validateRecordValue(label string, strings []string, values ...any) error {
	budget := newManifestValueBudget(maxRegistryRecordBytes, maxRegistryRecordNodes, maxRegistryCollectionEntries)
	for _, value := range strings {
		if err := budget.walk(value, 0); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	for _, value := range values {
		if value == nil {
			continue
		}
		if err := budget.walk(value, 0); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	return nil
}

func validateManifestResourceBounds(manifest *registryManifest) error {
	if manifest.BaseManifestID != nil && !manifestIDPattern.MatchString(*manifest.BaseManifestID) {
		return errors.New("base_manifest_id is invalid")
	}
	if err := validateRegistryCounts(manifest.Counts); err != nil {
		return err
	}
	for label, countLimit := range map[string][2]int{
		"sources":          {len(manifest.Sources), maxRegistrySources},
		"components":       {len(manifest.Components), maxRegistryComponents},
		"versions":         {len(manifest.Versions), maxRegistryVersions},
		"occurrences":      {len(manifest.Occurrences), maxRegistryOccurrences},
		"dependency_edges": {len(manifest.DependencyEdges), maxRegistryEdges},
		"gaps":             {len(manifest.Gaps), maxRegistryGaps},
	} {
		if countLimit[0] > countLimit[1] {
			return fmt.Errorf("registry %s exceed %d-record bound", label, countLimit[1])
		}
	}

	for index, source := range manifest.Sources {
		strings := []string{source.SourceID, source.SourceType, source.EvidenceURI, source.ContentHash}
		if err := validateExposedRow(fmt.Sprintf("source[%d]", index), strings...); err != nil {
			return err
		}
		if err := validateRecordValue(fmt.Sprintf("source[%d]", index), strings, source.Metadata); err != nil {
			return err
		}
	}
	for index, component := range manifest.Components {
		if len(component.Lifecycles) > maxRegistryLifecycles || len(component.OfficialChannels) > maxRegistryChannelsPerComponent ||
			len(component.OfficialChannelProposals) > maxRegistryChannelsPerComponent ||
			len(component.OfficialChannelSnapshots) > maxRegistryChannelsPerComponent ||
			len(component.OfficialResolutions) > maxRegistryChannelsPerComponent {
			return fmt.Errorf("component[%d] exceeds lifecycle or official-channel count bounds", index)
		}
		core := []string{component.ComponentID, component.Ecosystem, component.Kind, component.Name, component.Namespace, component.PURL}
		core = append(core, component.Lifecycles...)
		if err := validateExposedRow(fmt.Sprintf("component[%d]", index), core...); err != nil {
			return err
		}
		channelGroups := [][]map[string]any{component.OfficialChannels, component.OfficialChannelProposals,
			component.OfficialChannelSnapshots, component.OfficialResolutions}
		for groupIndex, group := range channelGroups {
			maximum := maxRegistryRecordBytes
			if groupIndex == 0 {
				maximum = maxRegistryToolRowBytes
			}
			for channelIndex, channel := range group {
				if err := validateLooseValue(fmt.Sprintf("component[%d].channel[%d][%d]", index, groupIndex, channelIndex),
					channel, maximum, maxRegistryRecordNodes, maxRegistryCollectionEntries); err != nil {
					return err
				}
			}
		}
		if err := validateRecordValue(fmt.Sprintf("component[%d]", index), core, component.Metadata,
			component.OfficialChannels, component.OfficialChannelProposals,
			component.OfficialChannelSnapshots, component.OfficialResolutions); err != nil {
			return err
		}
	}
	for index, version := range manifest.Versions {
		if len(version.Evidence) > maxRegistryEvidenceItems {
			return fmt.Errorf("version[%d] exceeds %d evidence entries", index, maxRegistryEvidenceItems)
		}
		core := []string{version.ComponentID, version.ComponentVersionID, version.ArtifactDigest, version.Constraint,
			version.Platform, version.ResolutionState, version.ResolvedVersion, version.SourceRef}
		exposed := []string{version.ComponentVersionID, boundString(version.ResolvedVersion, 512),
			boundString(version.Constraint, 512), boundString(version.SourceRef, 1024),
			boundString(version.ArtifactDigest, 512), boundString(version.Platform, 256),
			version.ResolutionState}
		for _, evidence := range version.Evidence[:minInt(4, len(version.Evidence))] {
			exposed = append(exposed, boundString(evidence, 512))
		}
		if err := validateExposedRow(fmt.Sprintf("version[%d]", index), exposed...); err != nil {
			return err
		}
		if err := validateRecordValue(fmt.Sprintf("version[%d]", index), core, version.Evidence, version.Metadata); err != nil {
			return err
		}
	}
	for index, occurrence := range manifest.Occurrences {
		strings := []string{occurrence.ComponentID, occurrence.ComponentVersionID, occurrence.DependencyScope,
			occurrence.Directness, occurrence.EvidenceLocator, occurrence.Lifecycle, occurrence.OccurrenceID,
			occurrence.RawValue, occurrence.Role, occurrence.RootID, occurrence.SourceID}
		if err := validateExposedRow(fmt.Sprintf("occurrence[%d]", index), strings...); err != nil {
			return err
		}
		if err := validateRecordValue(fmt.Sprintf("occurrence[%d]", index), strings, occurrence.Metadata); err != nil {
			return err
		}
	}
	for index, edge := range manifest.DependencyEdges {
		strings := []string{edge.Constraint, edge.EdgeID, edge.FromComponentVersionID, edge.Relationship,
			edge.Resolver, edge.Scope, edge.SourceOccurrenceID, edge.ToComponentVersionID}
		if err := validateExposedRow(fmt.Sprintf("edge[%d]", index), strings...); err != nil {
			return err
		}
		if err := validateRecordValue(fmt.Sprintf("edge[%d]", index), strings, edge.Metadata); err != nil {
			return err
		}
	}
	gapTypes := make(map[string]struct{})
	for index, gap := range manifest.Gaps {
		if len(gap.Evidence) > maxRegistryEvidenceItems {
			return fmt.Errorf("gap[%d] exceeds %d evidence entries", index, maxRegistryEvidenceItems)
		}
		core := []string{gap.ComponentID, gap.ComponentVersionID, gap.GapID, gap.GapType, gap.Message, gap.SourceID}
		if len(gap.GapType) > maxRegistryGapTypeBytes {
			return fmt.Errorf("gap[%d].gap_type exceeds %d-byte bound", index, maxRegistryGapTypeBytes)
		}
		exposed := []string{gap.ComponentID, gap.ComponentVersionID, gap.GapID, gap.GapType,
			boundString(gap.Message, 2048), gap.SourceID}
		for _, evidence := range gap.Evidence[:minInt(4, len(gap.Evidence))] {
			exposed = append(exposed, boundString(evidence, 512))
		}
		if err := validateExposedRow(fmt.Sprintf("gap[%d]", index), exposed...); err != nil {
			return err
		}
		if err := validateRecordValue(fmt.Sprintf("gap[%d]", index), core, gap.Evidence, gap.Metadata); err != nil {
			return err
		}
		gapTypes[gap.GapType] = struct{}{}
		if len(gapTypes) > maxRegistryGapTypes {
			return fmt.Errorf("registry exceeds %d unique gap types", maxRegistryGapTypes)
		}
	}

	for label, value := range map[string]any{
		"completeness": manifest.Completeness, "generator": manifest.Generator,
		"input_set": manifest.InputSet, "discovery_scope": manifest.DiscoveryScope,
		"integrity": manifest.Integrity,
	} {
		if value == nil && label == "discovery_scope" {
			continue
		}
		if err := validateLooseValue(label, value, maxRegistryTopObjectBytes, maxRegistryTopObjectNodes, maxRegistryTopCollection); err != nil {
			return err
		}
	}
	if err := validateCompletenessOutputBounds(manifest.Completeness); err != nil {
		return err
	}
	return validateReconciliationBounds(manifest.Reconciliation)
}

func validateRegistryCounts(counts map[string]int) error {
	if len(counts) != maxRegistryCountKeys {
		return fmt.Errorf("registry counts must contain exactly %d fields", maxRegistryCountKeys)
	}
	for key, count := range counts {
		if len(key) > maxRegistryCountKeyBytes {
			return fmt.Errorf("registry count key exceeds %d bytes", maxRegistryCountKeyBytes)
		}
		if _, accepted := registryCountKeys[key]; !accepted {
			return fmt.Errorf("registry counts contains unknown field %q", key)
		}
		if count < 0 {
			return fmt.Errorf("registry count %s is negative", key)
		}
	}
	return nil
}

// archeion-registry-sqlite-v1 predates the current six-field manifest count set.
// Keep its retired seventh counter at zero inside projection metadata so the
// deployed v0.6.0 reader can consume newly compiled projections. The source
// manifest and every broker response retain the authoritative six-field v2
// shape; this is only a versioned projection-format compatibility field.
func projectionCompatibleCounts(counts map[string]int) map[string]int {
	result := cloneIntMap(counts)
	result[projectionLegacyResolutionCount] = 0
	return result
}

func validateProjectionCounts(counts map[string]int) error {
	if len(counts) != maxRegistryCountKeys+1 || counts[projectionLegacyResolutionCount] != 0 {
		return errors.New("projection counts require the zero-valued v1 compatibility field")
	}
	manifestCounts := cloneIntMap(counts)
	delete(manifestCounts, projectionLegacyResolutionCount)
	return validateRegistryCounts(manifestCounts)
}

func manifestCountsFromProjection(counts map[string]int) map[string]int {
	result := cloneIntMap(counts)
	delete(result, projectionLegacyResolutionCount)
	return result
}

func validateReconciliationBounds(reconciliation map[string]any) error {
	if err := requireExactKeys(reconciliation, reconciliationKeys); err != nil {
		return fmt.Errorf("reconciliation shape: %w", err)
	}
	total := 0
	for _, kind := range []string{"added", "changed", "removed", "missing"} {
		items, ok := reconciliation[kind].([]any)
		if !ok {
			return fmt.Errorf("reconciliation.%s must be an array", kind)
		}
		total += len(items)
		if total > maxRegistryReconciliationItems {
			return fmt.Errorf("reconciliation exceeds %d change entries", maxRegistryReconciliationItems)
		}
		for index, item := range items {
			if err := validateLooseValue(fmt.Sprintf("reconciliation.%s[%d]", kind, index), item,
				maxRegistryChangeInputBytes, maxRegistryRecordNodes, maxRegistryCollectionEntries); err != nil {
				return err
			}
		}
	}
	if value := reconciliation["previous_manifest_id"]; value != nil {
		previous, ok := value.(string)
		if !ok || !manifestIDPattern.MatchString(previous) {
			return errors.New("reconciliation.previous_manifest_id is invalid")
		}
	}
	for _, field := range []string{"complete_mark", "removal_allowed"} {
		if _, ok := reconciliation[field].(bool); !ok {
			return fmt.Errorf("reconciliation.%s must be boolean", field)
		}
	}
	return validateLooseValue("reconciliation", reconciliation, maxRegistryReconciliationBytes,
		maxRegistryReconciliationNodes, maxRegistryReconciliationItems)
}

func validateCompletenessOutputBounds(completeness map[string]any) error {
	if _, ok := completeness["all_axes_complete"].(bool); !ok {
		return errors.New("completeness.all_axes_complete must be boolean")
	}
	for _, name := range []string{"input", "enumeration", "closure", "identity", "channel_review", "snapshots"} {
		axisValue, exists := completeness[name]
		if !exists {
			continue
		}
		axis, ok := axisValue.(map[string]any)
		if !ok {
			return fmt.Errorf("completeness.%s must be an object", name)
		}
		if state, exists := axis["state"]; exists {
			value, ok := state.(string)
			if !ok || len(value) > 64 {
				return fmt.Errorf("completeness.%s.state must be a string of at most 64 bytes", name)
			}
		}
		for _, field := range []string{"input_count", "required_slots", "accepted_slots", "accepted_available_channels", "immutable_verified_channels"} {
			if value, exists := axis[field]; exists && !isBoundedJSONNumber(value) {
				return fmt.Errorf("completeness.%s.%s must be a bounded number", name, field)
			}
		}
	}
	return nil
}

func isBoundedJSONNumber(value any) bool {
	switch typed := value.(type) {
	case json.Number:
		return len(typed.String()) <= 64
	case float32, float64, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}

func compactChangeRecordBounded(value any) (any, bool) {
	if err := validateLooseValue("change record", value, maxRegistryChangeInputBytes,
		maxRegistryRecordNodes, maxRegistryCollectionEntries); err != nil {
		return map[string]any{"state": "oversized_or_invalid", "truncated": true}, false
	}
	encoded, err := canonicalJSON(value)
	if err != nil || len(encoded) > maxRegistryChangeCanonicalBytes {
		return map[string]any{"state": "oversized_or_invalid", "truncated": true}, false
	}
	if len(encoded) <= 8<<10 {
		var result any
		if err := decodeStrict(encoded, &result); err == nil {
			return result, true
		}
	}
	return map[string]any{
		"content_hash": hashBytes(encoded), "size_bytes": len(encoded), "truncated": true,
	}, true
}
