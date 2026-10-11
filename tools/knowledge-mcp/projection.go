package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	projectionSchemaVersion = "1.0.0"
	projectionRecordKind    = "archeion_registry_sqlite_projection_receipt"
	projectionFormat        = "archeion-registry-sqlite-v1"
	projectionAuthority     = "candidate_partial"
	projectionApplicationID = 0x43415544 // "CAUD"
	projectionUserVersion   = 1
	projectionReceiptSuffix = ".receipt.json"
	projectionOpenTimeout   = 10 * time.Second
	maxProjectionJSONCell   = 1 << 20
	maxProjectionRowBudget  = 4 << 20
	maxProjectionSearchRows = 4096
	maxProjectionQueryTerms = 64
)

var errProjectionRowBudget = errors.New("projection query JSON row budget exhausted")

type projectionJSONBudget struct {
	used    int
	maximum int
}

func newProjectionJSONBudget() *projectionJSONBudget {
	return &projectionJSONBudget{maximum: maxProjectionRowBudget}
}

func (budget *projectionJSONBudget) add(values ...string) error {
	if budget == nil {
		return nil
	}
	additional := 0
	for _, value := range values {
		if len(value) > maxProjectionJSONCell {
			return fmt.Errorf("projection text/JSON cell exceeds %d-byte bound", maxProjectionJSONCell)
		}
		additional += len(value)
	}
	if additional > budget.maximum-budget.used {
		return errProjectionRowBudget
	}
	budget.used += additional
	return nil
}

var projectionTables = []string{
	"component_sources",
	"components",
	"gaps",
	"occurrences",
	"projection_meta",
	"relations",
	"sources",
	"versions",
}

var projectionColumns = map[string][]string{
	"projection_meta": {"key", "value"},
	"sources":         {"source_id", "source_type", "evidence_uri", "content_hash"},
	"components": {"component_id", "ecosystem", "kind", "name", "namespace", "purl", "lifecycles_json",
		"official_channel_required", "official_channels_json", "reviewed_available_channels", "version_count",
		"occurrence_count", "source_count", "gap_count", "dependency_count", "dependent_count"},
	"versions": {"component_version_id", "component_id", "resolved_version", "constraint_value", "source_ref",
		"artifact_digest", "platform", "resolution_state", "evidence_json"},
	"occurrences": {"occurrence_id", "component_id", "component_version_id", "source_id", "root_id", "lifecycle",
		"role", "dependency_scope", "directness", "optional", "evidence_locator", "raw_value"},
	"component_sources": {"component_id", "source_id"},
	"gaps":              {"gap_id", "gap_type", "component_id", "component_version_id", "source_id", "message", "evidence_json"},
	"relations": {"from_component_id", "to_component_id", "relationship", "scope", "optional", "edge_count",
		"evidence_occurrence_ids_json"},
}

var expectedProjectionSchemaSQL = parseProjectionSchemaSQL(projectionDDL)

type projectionReceipt struct {
	SchemaVersion         string         `json:"schema_version"`
	RecordKind            string         `json:"record_kind"`
	ProjectionFormat      string         `json:"projection_format"`
	AuthorityState        string         `json:"authority_state"`
	Compiler              string         `json:"compiler"`
	CompilerVersion       string         `json:"compiler_version"`
	SourceManifestID      string         `json:"source_manifest_id"`
	SourceManifestHash    string         `json:"source_manifest_hash"`
	SourceFileSHA256      string         `json:"source_file_sha256"`
	SourceSizeBytes       int64          `json:"source_size_bytes"`
	SourceGenerationState string         `json:"source_generation_state"`
	ProjectionSHA256      string         `json:"projection_sha256"`
	ProjectionSizeBytes   int64          `json:"projection_size_bytes"`
	TableCounts           map[string]int `json:"table_counts"`
}

type registryProjection struct {
	db           *sql.DB
	path         string
	receipt      projectionReceipt
	counts       map[string]int
	completeness map[string]any
	reconcile    map[string]any
}

func compileRegistryProjection(manifestPath, outputPath string, maximum int64) (projectionReceipt, error) {
	return compileRegistryProjectionWithPublishHook(manifestPath, outputPath, maximum, nil)
}

type projectionPublishPhase string

const (
	projectionPublishDatabase projectionPublishPhase = "projection"
	projectionPublishReceipt  projectionPublishPhase = "receipt"
)

type projectionPublishHook func(projectionPublishPhase) error

func compileRegistryProjectionWithPublishHook(manifestPath, outputPath string, maximum int64, hook projectionPublishHook) (projectionReceipt, error) {
	sourceHashBefore, sourceSizeBefore, err := hashBoundFile(manifestPath, maximum)
	if err != nil {
		return projectionReceipt{}, fmt.Errorf("hash source manifest before validation: %w", err)
	}
	manifest, err := loadRegistryManifest(manifestPath, maximum)
	if err != nil {
		return projectionReceipt{}, fmt.Errorf("validate source manifest: %w", err)
	}
	sourceHash, sourceSize, err := hashBoundFile(manifestPath, maximum)
	if err != nil {
		return projectionReceipt{}, fmt.Errorf("hash source manifest after validation: %w", err)
	}
	if sourceHash != sourceHashBefore || sourceSize != sourceSizeBefore {
		return projectionReceipt{}, errors.New("source manifest changed while it was validated")
	}
	publisher, err := openProjectionPublisher(outputPath)
	if err != nil {
		return projectionReceipt{}, fmt.Errorf("open projection publisher: %w", err)
	}
	defer publisher.close()

	privateDirectory, err := os.MkdirTemp("", "archeion-knowledge-mcp-projection-")
	if err != nil {
		return projectionReceipt{}, fmt.Errorf("create private projection workspace: %w", err)
	}
	defer os.RemoveAll(privateDirectory)
	if err := os.Chmod(privateDirectory, 0o700); err != nil {
		return projectionReceipt{}, fmt.Errorf("protect private projection workspace: %w", err)
	}
	temporaryPath := filepath.Join(privateDirectory, "projection.sqlite")
	temporary, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return projectionReceipt{}, fmt.Errorf("create private projection database: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return projectionReceipt{}, fmt.Errorf("close private projection database: %w", err)
	}

	counts, err := writeProjectionDatabase(temporaryPath, manifest, sourceHash, sourceSize)
	if err != nil {
		return projectionReceipt{}, err
	}
	if err := validateCompiledProjectionShape(temporaryPath); err != nil {
		return projectionReceipt{}, fmt.Errorf("validate compiled projection bounds: %w", err)
	}
	if err := syncRegularFile(temporaryPath); err != nil {
		return projectionReceipt{}, fmt.Errorf("durably sync projection: %w", err)
	}
	projectionHash, projectionSize, err := hashBoundFile(temporaryPath, maximum)
	if err != nil {
		return projectionReceipt{}, fmt.Errorf("hash projection: %w", err)
	}
	receipt := projectionReceipt{
		SchemaVersion: projectionSchemaVersion, RecordKind: projectionRecordKind,
		ProjectionFormat: projectionFormat, AuthorityState: projectionAuthority,
		Compiler: serverName, CompilerVersion: serverVersion,
		SourceManifestID: manifest.ManifestID, SourceManifestHash: manifestHash(manifest),
		SourceFileSHA256: sourceHash, SourceSizeBytes: sourceSize,
		SourceGenerationState: manifest.GenerationState,
		ProjectionSHA256:      projectionHash, ProjectionSizeBytes: projectionSize,
		TableCounts: counts,
	}
	receiptRaw, err := canonicalJSON(receipt)
	if err != nil {
		return projectionReceipt{}, fmt.Errorf("encode projection receipt: %w", err)
	}
	receiptRaw = append(receiptRaw, '\n')
	receiptPath := filepath.Join(privateDirectory, "projection.receipt.json")
	if err := writePrivateSyncedFile(receiptPath, receiptRaw); err != nil {
		return projectionReceipt{}, fmt.Errorf("stage private projection receipt: %w", err)
	}

	if err := publisher.publishPair(temporaryPath, projectionHash, projectionSize, receiptPath, receiptRaw, hook); err != nil {
		return projectionReceipt{}, fmt.Errorf("publish projection and receipt: %w", err)
	}
	return receipt, nil
}

func validateCompiledProjectionShape(path string) error {
	db, err := sql.Open("sqlite", sqliteReadOnlyURI(path))
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), projectionOpenTimeout)
	defer cancel()
	if _, err := db.ExecContext(ctx, "PRAGMA query_only=ON"); err != nil {
		return err
	}
	projection := &registryProjection{db: db}
	if err := projection.validateSchemaObjects(ctx); err != nil {
		return err
	}
	return projection.validateCellAndRowBounds(ctx)
}

func writeProjectionDatabase(path string, manifest *registryManifest, sourceHash string, sourceSize int64) (map[string]int, error) {
	db, err := sql.Open("sqlite", sqliteReadWriteURI(path))
	if err != nil {
		return nil, fmt.Errorf("open projection writer: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, statement := range []string{
		"PRAGMA page_size=4096",
		"PRAGMA journal_mode=OFF",
		"PRAGMA synchronous=OFF",
		"PRAGMA temp_store=MEMORY",
		"PRAGMA locking_mode=EXCLUSIVE",
		"PRAGMA foreign_keys=ON",
		fmt.Sprintf("PRAGMA application_id=%d", projectionApplicationID),
		fmt.Sprintf("PRAGMA user_version=%d", projectionUserVersion),
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return nil, fmt.Errorf("configure projection writer: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, projectionDDL); err != nil {
		return nil, fmt.Errorf("create projection schema: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin projection transaction: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()

	meta := map[string]any{
		"schema_version":          projectionSchemaVersion,
		"projection_format":       projectionFormat,
		"authority_state":         projectionAuthority,
		"source_manifest_id":      manifest.ManifestID,
		"source_manifest_hash":    manifestHash(manifest),
		"source_file_sha256":      sourceHash,
		"source_size_bytes":       sourceSize,
		"source_generation_state": manifest.GenerationState,
		"counts":                  projectionCompatibleCounts(manifest.Counts),
		"completeness":            manifest.Completeness,
		"reconciliation":          manifest.Reconciliation,
	}
	metaKeys := make([]string, 0, len(meta))
	for key := range meta {
		metaKeys = append(metaKeys, key)
	}
	sort.Strings(metaKeys)
	for _, key := range metaKeys {
		encoded, encodeErr := canonicalJSON(meta[key])
		if encodeErr != nil {
			return nil, fmt.Errorf("encode projection metadata %s: %w", key, encodeErr)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO projection_meta(key,value) VALUES(?,?)", key, string(encoded)); err != nil {
			return nil, fmt.Errorf("insert projection metadata %s: %w", key, err)
		}
	}

	if err := insertProjectionRows(ctx, tx, manifest); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit projection: %w", err)
	}
	rollback = false
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		return nil, fmt.Errorf("vacuum projection: %w", err)
	}
	if err := db.Close(); err != nil {
		return nil, fmt.Errorf("close projection writer: %w", err)
	}

	return map[string]int{
		"sources":           len(manifest.Sources),
		"components":        len(manifest.Components),
		"versions":          len(manifest.Versions),
		"occurrences":       len(manifest.Occurrences),
		"gaps":              len(manifest.Gaps),
		"relations":         projectionRelationCount(manifest),
		"component_sources": projectionComponentSourceCount(manifest),
	}, nil
}

const projectionDDL = `
CREATE TABLE projection_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE sources (
  source_id TEXT PRIMARY KEY,
  source_type TEXT NOT NULL,
  evidence_uri TEXT NOT NULL,
  content_hash TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE components (
  component_id TEXT PRIMARY KEY,
  ecosystem TEXT NOT NULL,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  namespace TEXT NOT NULL,
  purl TEXT NOT NULL,
  lifecycles_json TEXT NOT NULL,
  official_channel_required INTEGER NOT NULL CHECK(official_channel_required IN (0,1)),
  official_channels_json TEXT NOT NULL,
  reviewed_available_channels INTEGER NOT NULL,
  version_count INTEGER NOT NULL,
  occurrence_count INTEGER NOT NULL,
  source_count INTEGER NOT NULL,
  gap_count INTEGER NOT NULL,
  dependency_count INTEGER NOT NULL,
  dependent_count INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX components_name_idx ON components(name COLLATE NOCASE, component_id);
CREATE INDEX components_purl_idx ON components(purl COLLATE NOCASE, component_id);
CREATE INDEX components_filter_idx ON components(ecosystem COLLATE NOCASE, kind COLLATE NOCASE, component_id);
CREATE TABLE versions (
  component_version_id TEXT PRIMARY KEY,
  component_id TEXT NOT NULL REFERENCES components(component_id),
  resolved_version TEXT NOT NULL,
  constraint_value TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  artifact_digest TEXT NOT NULL,
  platform TEXT NOT NULL,
  resolution_state TEXT NOT NULL,
  evidence_json TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX versions_component_idx ON versions(component_id, component_version_id);
CREATE TABLE occurrences (
  occurrence_id TEXT PRIMARY KEY,
  component_id TEXT NOT NULL REFERENCES components(component_id),
  component_version_id TEXT NOT NULL REFERENCES versions(component_version_id),
  source_id TEXT NOT NULL REFERENCES sources(source_id),
  root_id TEXT NOT NULL,
  lifecycle TEXT NOT NULL,
  role TEXT NOT NULL,
  dependency_scope TEXT NOT NULL,
  directness TEXT NOT NULL,
  optional INTEGER NOT NULL CHECK(optional IN (0,1)),
  evidence_locator TEXT NOT NULL,
  raw_value TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX occurrences_component_idx ON occurrences(component_id, occurrence_id);
CREATE TABLE component_sources (
  component_id TEXT NOT NULL REFERENCES components(component_id),
  source_id TEXT NOT NULL REFERENCES sources(source_id),
  PRIMARY KEY(component_id, source_id)
) WITHOUT ROWID;
CREATE INDEX component_sources_source_idx ON component_sources(source_id, component_id);
CREATE TABLE gaps (
  gap_id TEXT PRIMARY KEY,
  gap_type TEXT NOT NULL,
  component_id TEXT NOT NULL,
  component_version_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  message TEXT NOT NULL,
  evidence_json TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX gaps_component_idx ON gaps(component_id, gap_type, gap_id);
CREATE INDEX gaps_type_idx ON gaps(gap_type, gap_id);
CREATE TABLE relations (
  from_component_id TEXT NOT NULL REFERENCES components(component_id),
  to_component_id TEXT NOT NULL REFERENCES components(component_id),
  relationship TEXT NOT NULL,
  scope TEXT NOT NULL,
  optional INTEGER NOT NULL CHECK(optional IN (0,1)),
  edge_count INTEGER NOT NULL,
  evidence_occurrence_ids_json TEXT NOT NULL,
  PRIMARY KEY(from_component_id, to_component_id, relationship, scope, optional)
) WITHOUT ROWID;
CREATE INDEX relations_to_idx ON relations(to_component_id, from_component_id, relationship, scope, optional);
`

func insertProjectionRows(ctx context.Context, tx *sql.Tx, manifest *registryManifest) error {
	for _, source := range manifest.Sources {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sources(source_id,source_type,evidence_uri,content_hash) VALUES(?,?,?,?)`,
			source.SourceID, source.SourceType, source.EvidenceURI, source.ContentHash); err != nil {
			return fmt.Errorf("insert source %s: %w", source.SourceID, err)
		}
	}
	for index := range manifest.Components {
		component := &manifest.Components[index]
		lifecycles, err := canonicalJSON(component.Lifecycles)
		if err != nil {
			return fmt.Errorf("encode component lifecycles %s: %w", component.ComponentID, err)
		}
		channels, err := canonicalJSON(component.OfficialChannels)
		if err != nil {
			return fmt.Errorf("encode component channels %s: %w", component.ComponentID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO components(
component_id,ecosystem,kind,name,namespace,purl,lifecycles_json,official_channel_required,
official_channels_json,reviewed_available_channels,version_count,occurrence_count,source_count,
gap_count,dependency_count,dependent_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			component.ComponentID, component.Ecosystem, component.Kind, component.Name, component.Namespace,
			component.PURL, string(lifecycles), boolInt(component.OfficialChannelRequired), string(channels),
			reviewedAvailableChannels(component.OfficialChannels), len(manifest.versionsByComp[component.ComponentID]),
			len(manifest.occurrencesByComp[component.ComponentID]), len(manifest.sourcesByComp[component.ComponentID]),
			len(manifest.gapsByComp[component.ComponentID]), len(manifest.relationsFromComp[component.ComponentID]),
			len(manifest.relationsToComp[component.ComponentID])); err != nil {
			return fmt.Errorf("insert component %s: %w", component.ComponentID, err)
		}
	}
	for _, version := range manifest.Versions {
		evidence, err := canonicalJSON(version.Evidence)
		if err != nil {
			return fmt.Errorf("encode version evidence %s: %w", version.ComponentVersionID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO versions(component_version_id,component_id,resolved_version,
constraint_value,source_ref,artifact_digest,platform,resolution_state,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)`,
			version.ComponentVersionID, version.ComponentID, version.ResolvedVersion, version.Constraint,
			version.SourceRef, version.ArtifactDigest, version.Platform, version.ResolutionState, string(evidence)); err != nil {
			return fmt.Errorf("insert version %s: %w", version.ComponentVersionID, err)
		}
	}
	for _, occurrence := range manifest.Occurrences {
		if _, err := tx.ExecContext(ctx, `INSERT INTO occurrences(occurrence_id,component_id,component_version_id,
source_id,root_id,lifecycle,role,dependency_scope,directness,optional,evidence_locator,raw_value)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, occurrence.OccurrenceID, occurrence.ComponentID,
			occurrence.ComponentVersionID, occurrence.SourceID, occurrence.RootID, occurrence.Lifecycle,
			occurrence.Role, occurrence.DependencyScope, occurrence.Directness, boolInt(occurrence.Optional),
			occurrence.EvidenceLocator, occurrence.RawValue); err != nil {
			return fmt.Errorf("insert occurrence %s: %w", occurrence.OccurrenceID, err)
		}
	}
	componentIDs := make([]string, 0, len(manifest.sourcesByComp))
	for componentID := range manifest.sourcesByComp {
		componentIDs = append(componentIDs, componentID)
	}
	sort.Strings(componentIDs)
	for _, componentID := range componentIDs {
		for _, source := range manifest.sourcesByComp[componentID] {
			if _, err := tx.ExecContext(ctx, `INSERT INTO component_sources(component_id,source_id) VALUES(?,?)`, componentID, source.SourceID); err != nil {
				return fmt.Errorf("insert component source %s/%s: %w", componentID, source.SourceID, err)
			}
		}
	}
	for _, gap := range manifest.Gaps {
		evidence, err := canonicalJSON(gap.Evidence)
		if err != nil {
			return fmt.Errorf("encode gap evidence %s: %w", gap.GapID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO gaps(gap_id,gap_type,component_id,component_version_id,
source_id,message,evidence_json) VALUES(?,?,?,?,?,?,?)`, gap.GapID, gap.GapType, gap.ComponentID,
			gap.ComponentVersionID, gap.SourceID, gap.Message, string(evidence)); err != nil {
			return fmt.Errorf("insert gap %s: %w", gap.GapID, err)
		}
	}
	relations := projectionRelations(manifest)
	for _, relation := range relations {
		evidence, err := canonicalJSON(relation.EvidenceOccurrences)
		if err != nil {
			return fmt.Errorf("encode relation evidence: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO relations(from_component_id,to_component_id,relationship,
scope,optional,edge_count,evidence_occurrence_ids_json) VALUES(?,?,?,?,?,?,?)`, relation.FromComponentID,
			relation.ToComponentID, relation.Relationship, relation.Scope, boolInt(relation.Optional),
			relation.EdgeCount, string(evidence)); err != nil {
			return fmt.Errorf("insert relation %s/%s: %w", relation.FromComponentID, relation.ToComponentID, err)
		}
	}
	return nil
}

func projectionRelations(manifest *registryManifest) []registryRelation {
	result := make([]registryRelation, 0)
	for _, relations := range manifest.relationsFromComp {
		result = append(result, relations...)
	}
	sort.Slice(result, func(i, j int) bool {
		return relationLess(result[i], result[j])
	})
	return result
}

func projectionRelationCount(manifest *registryManifest) int {
	count := 0
	for _, relations := range manifest.relationsFromComp {
		count += len(relations)
	}
	return count
}

func projectionComponentSourceCount(manifest *registryManifest) int {
	count := 0
	for _, sources := range manifest.sourcesByComp {
		count += len(sources)
	}
	return count
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func sqliteReadWriteURI(path string) string {
	value := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := value.Query()
	query.Set("mode", "rwc")
	query.Set("cache", "private")
	value.RawQuery = query.Encode()
	return value.String()
}

func sqliteReadOnlyURI(path string) string {
	value := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := value.Query()
	query.Set("mode", "ro")
	query.Set("immutable", "1")
	query.Set("cache", "private")
	value.RawQuery = query.Encode()
	return value.String()
}

func openRegistryProjection(path string, maximum int64) (*registryProjection, error) {
	if err := validateDirectoryPathNoSymlinks(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("validate projection parent: %w", err)
	}
	if err := requireReadOnlyRegular(path); err != nil {
		return nil, fmt.Errorf("validate immutable projection mode: %w", err)
	}
	if err := requireReadOnlyRegular(path + projectionReceiptSuffix); err != nil {
		return nil, fmt.Errorf("validate immutable projection receipt mode: %w", err)
	}
	receiptRaw, err := readBoundRegular(path+projectionReceiptSuffix, maxControlObjectBytes, true)
	if err != nil {
		return nil, fmt.Errorf("read projection receipt: %w", err)
	}
	var receipt projectionReceipt
	if err := decodeStrictTyped(receiptRaw, &receipt); err != nil {
		return nil, fmt.Errorf("decode projection receipt: %w", err)
	}
	if err := validateProjectionReceipt(receipt); err != nil {
		return nil, err
	}
	canonicalReceipt, err := canonicalJSON(receipt)
	if err != nil {
		return nil, fmt.Errorf("canonicalize projection receipt: %w", err)
	}
	canonicalReceipt = append(canonicalReceipt, '\n')
	if !stringBytesEqual(receiptRaw, canonicalReceipt) {
		return nil, errors.New("projection receipt is not in canonical immutable encoding")
	}
	projectionHash, projectionSize, err := hashBoundFile(path, maximum)
	if err != nil {
		return nil, fmt.Errorf("hash projection: %w", err)
	}
	if projectionHash != receipt.ProjectionSHA256 || projectionSize != receipt.ProjectionSizeBytes {
		return nil, errors.New("projection bytes do not match the immutable receipt binding")
	}

	db, err := sql.Open("sqlite", sqliteReadOnlyURI(path))
	if err != nil {
		return nil, fmt.Errorf("open compact projection: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	projection := &registryProjection{db: db, path: path, receipt: receipt}
	if err := projection.validate(); err != nil {
		db.Close()
		return nil, err
	}
	projectionHashAfter, projectionSizeAfter, err := hashBoundFile(path, maximum)
	if err != nil || projectionHashAfter != projectionHash || projectionSizeAfter != projectionSize {
		db.Close()
		return nil, errors.New("projection changed while it was opened and validated")
	}
	receiptRawAfter, err := readBoundRegular(path+projectionReceiptSuffix, maxControlObjectBytes, true)
	if err != nil || !stringBytesEqual(receiptRawAfter, receiptRaw) {
		db.Close()
		return nil, errors.New("projection receipt changed while the projection was opened")
	}
	return projection, nil
}

func validateProjectionReceipt(receipt projectionReceipt) error {
	if receipt.SchemaVersion != projectionSchemaVersion || receipt.RecordKind != projectionRecordKind ||
		receipt.ProjectionFormat != projectionFormat || receipt.AuthorityState != projectionAuthority ||
		receipt.Compiler != serverName || receipt.CompilerVersion == "" ||
		receipt.SourceGenerationState != "candidate" {
		return errors.New("projection receipt schema, compiler, or candidate authority state is invalid")
	}
	if !manifestIDPattern.MatchString(receipt.SourceManifestID) || !sha256Pattern.MatchString(receipt.SourceManifestHash) ||
		receipt.SourceManifestID != "mft-"+strings.TrimPrefix(receipt.SourceManifestHash, "sha256:") ||
		!sha256Pattern.MatchString(receipt.SourceFileSHA256) || !sha256Pattern.MatchString(receipt.ProjectionSHA256) ||
		receipt.SourceSizeBytes <= 0 || receipt.ProjectionSizeBytes <= 0 {
		return errors.New("projection receipt identity binding is invalid")
	}
	expectedCountTables := []string{"component_sources", "components", "gaps", "occurrences", "relations", "sources", "versions"}
	for _, table := range expectedCountTables {
		count, exists := receipt.TableCounts[table]
		if !exists || count < 0 {
			return fmt.Errorf("projection receipt has invalid count for %s", table)
		}
	}
	if len(receipt.TableCounts) != len(expectedCountTables) {
		return errors.New("projection receipt table count set is invalid")
	}
	return nil
}

func (projection *registryProjection) validate() error {
	ctx, cancel := context.WithTimeout(context.Background(), projectionOpenTimeout)
	defer cancel()
	if _, err := projection.db.ExecContext(ctx, "PRAGMA query_only=ON"); err != nil {
		return fmt.Errorf("force projection query-only mode: %w", err)
	}
	var applicationID, userVersion int
	if err := projection.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil || applicationID != projectionApplicationID {
		return errors.New("projection application identity is invalid")
	}
	if err := projection.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion); err != nil || userVersion != projectionUserVersion {
		return errors.New("projection schema version is invalid")
	}
	var check string
	if err := projection.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return fmt.Errorf("projection integrity check failed: %s", check)
	}
	rows, err := projection.db.QueryContext(ctx, `SELECT name FROM sqlite_schema
WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return fmt.Errorf("enumerate projection tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, name)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if strings.Join(tables, "\x00") != strings.Join(projectionTables, "\x00") {
		return fmt.Errorf("projection table set is invalid: %v", tables)
	}
	if err := projection.validateSchemaObjects(ctx); err != nil {
		return err
	}
	if err := projection.validateCellAndRowBounds(ctx); err != nil {
		return err
	}
	meta, err := projection.readMeta(ctx)
	if err != nil {
		return err
	}
	for key, expected := range map[string]string{
		"schema_version":          projectionSchemaVersion,
		"projection_format":       projectionFormat,
		"authority_state":         projectionAuthority,
		"source_manifest_id":      projection.receipt.SourceManifestID,
		"source_manifest_hash":    projection.receipt.SourceManifestHash,
		"source_file_sha256":      projection.receipt.SourceFileSHA256,
		"source_generation_state": projection.receipt.SourceGenerationState,
	} {
		var got string
		if err := json.Unmarshal([]byte(meta[key]), &got); err != nil || got != expected {
			return fmt.Errorf("projection metadata binding %s is invalid", key)
		}
	}
	var sourceSize int64
	if err := json.Unmarshal([]byte(meta["source_size_bytes"]), &sourceSize); err != nil || sourceSize != projection.receipt.SourceSizeBytes {
		return errors.New("projection source size binding is invalid")
	}
	if err := decodeProjectionMeta(meta["counts"], &projection.counts); err != nil {
		return fmt.Errorf("decode projection counts: %w", err)
	}
	if err := decodeProjectionMeta(meta["completeness"], &projection.completeness); err != nil {
		return fmt.Errorf("decode projection completeness: %w", err)
	}
	if err := decodeProjectionMeta(meta["reconciliation"], &projection.reconcile); err != nil {
		return fmt.Errorf("decode projection reconciliation: %w", err)
	}
	if err := validateProjectionCounts(projection.counts); err != nil {
		return fmt.Errorf("validate projection counts: %w", err)
	}
	if err := validateLooseValue("projection completeness", projection.completeness,
		maxRegistryTopObjectBytes, maxRegistryTopObjectNodes, maxRegistryTopCollection); err != nil {
		return err
	}
	if err := validateCompletenessOutputBounds(projection.completeness); err != nil {
		return fmt.Errorf("validate projection completeness: %w", err)
	}
	if err := validateReconciliationBounds(projection.reconcile); err != nil {
		return fmt.Errorf("validate projection reconciliation: %w", err)
	}
	for table, expected := range projection.receipt.TableCounts {
		var count int
		query := "SELECT COUNT(*) FROM " + table
		if err := projection.db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != expected {
			return fmt.Errorf("projection table count mismatch for %s", table)
		}
	}
	return nil
}

func (projection *registryProjection) validateSchemaObjects(ctx context.Context) error {
	rows, err := projection.db.QueryContext(ctx, `SELECT type,name,sql FROM sqlite_schema
WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		return fmt.Errorf("inspect projection schema SQL: %w", err)
	}
	seen := make(map[string]struct{}, len(expectedProjectionSchemaSQL))
	for rows.Next() {
		var objectType, name, rawSQL string
		if err := rows.Scan(&objectType, &name, &rawSQL); err != nil {
			rows.Close()
			return err
		}
		key := objectType + ":" + name
		expected, exists := expectedProjectionSchemaSQL[key]
		if !exists {
			rows.Close()
			return fmt.Errorf("unexpected projection schema object %s", key)
		}
		if canonicalSQLiteSchemaSQL(rawSQL) != expected {
			rows.Close()
			return fmt.Errorf("projection schema SQL for %s differs from the exact versioned DDL", key)
		}
		seen[key] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(seen) != len(expectedProjectionSchemaSQL) {
		return fmt.Errorf("projection schema object set is incomplete: got %d want %d", len(seen), len(expectedProjectionSchemaSQL))
	}
	var unsafeObjects int
	if err := projection.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE type IN ('view','trigger')`).Scan(&unsafeObjects); err != nil {
		return err
	}
	if unsafeObjects != 0 {
		return errors.New("projection views and triggers are forbidden")
	}
	return nil
}

func parseProjectionSchemaSQL(ddl string) map[string]string {
	result := make(map[string]string)
	for _, raw := range strings.Split(ddl, ";") {
		statement := canonicalSQLiteSchemaSQL(raw)
		if statement == "" {
			continue
		}
		fields := strings.Fields(statement)
		if len(fields) < 3 || fields[0] != "CREATE" || (fields[1] != "TABLE" && fields[1] != "INDEX") {
			panic("invalid projection DDL statement: " + statement)
		}
		key := strings.ToLower(fields[1]) + ":" + fields[2]
		if _, duplicate := result[key]; duplicate {
			panic("duplicate projection DDL object: " + key)
		}
		result[key] = statement
	}
	return result
}

func canonicalSQLiteSchemaSQL(value string) string {
	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), ";"))
	return strings.Join(strings.Fields(value), " ")
}

func (projection *registryProjection) validateCellAndRowBounds(ctx context.Context) error {
	for _, table := range projectionTables {
		columns := projectionColumns[table]
		cellConditions := make([]string, 0, len(columns))
		rowLengths := make([]string, 0, len(columns))
		for _, column := range columns {
			byteLength := "length(CAST(" + column + " AS BLOB))"
			cellConditions = append(cellConditions, byteLength+" > ?")
			rowLengths = append(rowLengths, "coalesce("+byteLength+",0)")
		}
		arguments := make([]any, len(columns))
		for index := range arguments {
			arguments[index] = maxProjectionJSONCell
		}
		var oversized int
		query := "SELECT EXISTS(SELECT 1 FROM " + table + " WHERE " + strings.Join(cellConditions, " OR ") + " LIMIT 1)"
		if err := projection.db.QueryRowContext(ctx, query, arguments...).Scan(&oversized); err != nil {
			return fmt.Errorf("validate projection cell bounds for %s: %w", table, err)
		}
		if oversized != 0 {
			return fmt.Errorf("projection table %s contains an oversized cell", table)
		}
		rowQuery := "SELECT EXISTS(SELECT 1 FROM " + table + " WHERE " + strings.Join(rowLengths, "+") + " > ? LIMIT 1)"
		if err := projection.db.QueryRowContext(ctx, rowQuery, maxProjectionRowBudget).Scan(&oversized); err != nil {
			return fmt.Errorf("validate projection row bounds for %s: %w", table, err)
		}
		if oversized != 0 {
			return fmt.Errorf("projection table %s contains an oversized row", table)
		}
	}
	return nil
}

func (projection *registryProjection) readMeta(ctx context.Context) (map[string]string, error) {
	rows, err := projection.db.QueryContext(ctx, "SELECT key,value FROM projection_meta ORDER BY key")
	if err != nil {
		return nil, fmt.Errorf("read projection metadata: %w", err)
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		result[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	expected := []string{"authority_state", "completeness", "counts", "projection_format", "reconciliation",
		"schema_version", "source_file_sha256", "source_generation_state", "source_manifest_hash",
		"source_manifest_id", "source_size_bytes"}
	if len(result) != len(expected) {
		return nil, errors.New("projection metadata key set is invalid")
	}
	for _, key := range expected {
		if _, ok := result[key]; !ok {
			return nil, fmt.Errorf("projection metadata is missing %s", key)
		}
	}
	return result, nil
}

func decodeProjectionMeta(raw string, target any) error {
	if raw == "" {
		return errors.New("metadata value is missing")
	}
	if len(raw) > maxProjectionJSONCell {
		return fmt.Errorf("projection JSON cell exceeds %d-byte bound", maxProjectionJSONCell)
	}
	return decodeStrict([]byte(raw), target)
}

func (projection *registryProjection) manifestHeader() *registryManifest {
	header := &registryManifest{
		JSONSchema:    "https://json-schema.org/draft/2020-12/schema",
		SchemaVersion: "2.0.0", RecordKind: "generated_discovery_manifest",
		ManifestVersion: 2, ManifestID: projection.receipt.SourceManifestID,
		GenerationState: projection.receipt.SourceGenerationState,
		Counts:          manifestCountsFromProjection(projection.counts), Completeness: cloneJSONMap(projection.completeness),
		Reconciliation: cloneJSONMap(projection.reconcile),
		Integrity:      map[string]any{"manifest_hash": projection.receipt.SourceManifestHash},
	}
	if base, ok := projection.reconcile["previous_manifest_id"].(string); ok && manifestIDPattern.MatchString(base) {
		header.BaseManifestID = &base
	}
	return header
}

func hashBoundFile(path string, maximum int64) (string, int64, error) {
	file, size, err := openBoundRegular(path, maximum, true)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	openedBefore, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maximum+1))
	if err != nil {
		return "", 0, err
	}
	if written != size || written > maximum {
		return "", 0, errors.New("file changed while hashing or exceeded its bound")
	}
	openedAfter, err := file.Stat()
	if err != nil || openedAfter.Size() != openedBefore.Size() || !openedAfter.ModTime().Equal(openedBefore.ModTime()) {
		return "", 0, errors.New("file metadata changed while hashing")
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || pathAfter.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedBefore, pathAfter) {
		return "", 0, errors.New("file path changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), size, nil
}

type projectionPublisher struct {
	parentPath     string
	root           *os.Root
	parentInfo     fs.FileInfo
	projectionName string
	receiptName    string
}

func openProjectionPublisher(outputPath string) (*projectionPublisher, error) {
	absolute, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		return nil, err
	}
	parentPath := filepath.Dir(absolute)
	projectionName := filepath.Base(absolute)
	if projectionName == "." || projectionName == ".." || projectionName == string(filepath.Separator) ||
		projectionName == "" || strings.ContainsAny(projectionName, `/\\`) || strings.ContainsRune(projectionName, '\x00') {
		return nil, errors.New("projection output must have a safe child filename")
	}
	if err := validateDirectoryPathNoSymlinks(parentPath); err != nil {
		return nil, fmt.Errorf("validate projection parent: %w", err)
	}
	before, err := os.Lstat(parentPath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("projection parent is not a non-symlink directory")
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		root.Close()
		return nil, errors.New("projection parent changed while it was opened")
	}
	publisher := &projectionPublisher{
		parentPath: parentPath, root: root, parentInfo: opened,
		projectionName: projectionName, receiptName: projectionName + projectionReceiptSuffix,
	}
	if err := publisher.verifyBinding(); err != nil {
		root.Close()
		return nil, err
	}
	return publisher, nil
}

func (publisher *projectionPublisher) close() error {
	if publisher == nil || publisher.root == nil {
		return nil
	}
	return publisher.root.Close()
}

func (publisher *projectionPublisher) verifyBinding() error {
	if err := validateDirectoryPathNoSymlinks(publisher.parentPath); err != nil {
		return errors.New("projection parent path became unsafe")
	}
	pathInfo, err := os.Lstat(publisher.parentPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return errors.New("projection parent is no longer a non-symlink directory")
	}
	opened, err := publisher.root.Stat(".")
	if err != nil || !os.SameFile(publisher.parentInfo, opened) || !os.SameFile(publisher.parentInfo, pathInfo) {
		return errors.New("projection parent identity changed during publication")
	}
	return nil
}

type rootedProjectionStage struct {
	name   string
	hash   string
	size   int64
	target string
	info   fs.FileInfo
}

func (publisher *projectionPublisher) publishPair(databasePath, databaseHash string, databaseSize int64, receiptPath string, receiptRaw []byte, hook projectionPublishHook) error {
	if databaseSize <= 0 || int64(len(receiptRaw)) <= 0 || int64(len(receiptRaw)) > maxControlObjectBytes {
		return errors.New("projection publication inputs exceed their bounds")
	}
	receiptDigest := sha256.Sum256(receiptRaw)
	receiptHash := "sha256:" + hex.EncodeToString(receiptDigest[:])

	databaseExists, err := publisher.targetMatches(publisher.projectionName, databaseHash, databaseSize)
	if err != nil {
		return fmt.Errorf("preflight immutable projection: %w", err)
	}
	receiptExists, err := publisher.targetMatches(publisher.receiptName, receiptHash, int64(len(receiptRaw)))
	if err != nil {
		return fmt.Errorf("preflight immutable receipt: %w", err)
	}
	if databaseExists && receiptExists {
		return publisher.verifyBinding()
	}

	stages := make([]rootedProjectionStage, 0, 2)
	cleanupStages := func() {
		for _, stage := range stages {
			publisher.removeStageIfSame(stage)
		}
	}
	defer cleanupStages()
	if !databaseExists {
		stage, err := publisher.stagePrivateFile(databasePath, publisher.projectionName, databaseHash, databaseSize)
		if err != nil {
			return fmt.Errorf("stage immutable projection: %w", err)
		}
		stages = append(stages, stage)
	}
	if !receiptExists {
		stage, err := publisher.stagePrivateFile(receiptPath, publisher.receiptName, receiptHash, int64(len(receiptRaw)))
		if err != nil {
			return fmt.Errorf("stage immutable receipt: %w", err)
		}
		stages = append(stages, stage)
	}

	created := make([]rootedProjectionStage, 0, len(stages))
	rollback := func() {
		for index := len(created) - 1; index >= 0; index-- {
			publisher.removeTargetIfStageLink(created[index])
		}
		cleanupStages()
		_ = publisher.syncDirectory()
	}
	for _, stage := range stages {
		phase := projectionPublishDatabase
		if stage.target == publisher.receiptName {
			phase = projectionPublishReceipt
		}
		if err := publisher.verifyBinding(); err != nil {
			rollback()
			return err
		}
		if hook != nil {
			if err := hook(phase); err != nil {
				rollback()
				return err
			}
		}
		if err := publisher.root.Link(stage.name, stage.target); err != nil {
			if !errors.Is(err, fs.ErrExist) {
				rollback()
				return err
			}
			matches, checkErr := publisher.targetMatches(stage.target, stage.hash, stage.size)
			if checkErr != nil || !matches {
				rollback()
				return errors.New("immutable projection publication collision")
			}
		} else {
			created = append(created, stage)
		}
		if err := publisher.verifyBinding(); err != nil {
			rollback()
			return err
		}
		matches, err := publisher.targetMatches(stage.target, stage.hash, stage.size)
		if err != nil || !matches {
			rollback()
			return errors.New("published projection artifact failed its rooted identity check")
		}
	}

	if err := publisher.syncDirectory(); err != nil {
		rollback()
		return fmt.Errorf("sync projection parent: %w", err)
	}
	if err := publisher.verifyBinding(); err != nil {
		rollback()
		return err
	}
	cleanupStages()
	stages = nil
	if err := publisher.syncDirectory(); err != nil {
		return fmt.Errorf("sync projection staging cleanup: %w", err)
	}
	if err := publisher.verifyBinding(); err != nil {
		return err
	}
	return nil
}

func (publisher *projectionPublisher) stagePrivateFile(sourcePath, target, expectedHash string, expectedSize int64) (rootedProjectionStage, error) {
	if err := publisher.verifyBinding(); err != nil {
		return rootedProjectionStage{}, err
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return rootedProjectionStage{}, err
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Size() != expectedSize {
		return rootedProjectionStage{}, errors.New("private projection artifact is not the expected regular file")
	}
	name, err := projectionRandomChild(".archeion-projection-stage-")
	if err != nil {
		return rootedProjectionStage{}, err
	}
	destination, err := publisher.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return rootedProjectionStage{}, err
	}
	createdInfo, err := destination.Stat()
	if err != nil || !createdInfo.Mode().IsRegular() {
		destination.Close()
		_ = publisher.root.Remove(name)
		return rootedProjectionStage{}, errors.New("rooted projection stage identity is unavailable")
	}
	stage := rootedProjectionStage{name: name, hash: expectedHash, size: expectedSize, target: target, info: createdInfo}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(source, expectedSize+1))
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != expectedSize ||
		"sha256:"+hex.EncodeToString(hash.Sum(nil)) != expectedHash {
		publisher.removeStageIfSame(stage)
		return rootedProjectionStage{}, errors.New("private projection artifact changed or failed while staging")
	}
	matches, err := publisher.targetMatches(name, expectedHash, expectedSize)
	if err != nil || !matches {
		publisher.removeStageIfSame(stage)
		return rootedProjectionStage{}, errors.New("rooted projection stage failed its identity check")
	}
	stageInfo, err := publisher.root.Lstat(name)
	if err != nil || !os.SameFile(stage.info, stageInfo) {
		publisher.removeStageIfSame(stage)
		return rootedProjectionStage{}, errors.New("rooted projection stage identity became unavailable")
	}
	if err := publisher.verifyBinding(); err != nil {
		publisher.removeStageIfSame(stage)
		return rootedProjectionStage{}, err
	}
	return stage, nil
}

func (publisher *projectionPublisher) targetMatches(name, expectedHash string, expectedSize int64) (bool, error) {
	info, err := publisher.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != expectedSize || info.Mode().Perm()&0o222 != 0 {
		return false, errors.New("immutable projection target has an unsafe type, size, or mode")
	}
	file, err := publisher.root.Open(name)
	if err != nil {
		return false, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return false, errors.New("immutable projection target changed before read")
	}
	digest := sha256.New()
	size, readErr := io.Copy(digest, io.LimitReader(file, expectedSize+1))
	closeErr := file.Close()
	after, statErr := publisher.root.Lstat(name)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(opened, after) || size != expectedSize ||
		after.Size() != expectedSize || after.ModTime() != opened.ModTime() {
		return false, errors.New("immutable projection target changed during read")
	}
	return "sha256:"+hex.EncodeToString(digest.Sum(nil)) == expectedHash, nil
}

func (publisher *projectionPublisher) removeTargetIfStageLink(stage rootedProjectionStage) {
	targetInfo, targetErr := publisher.root.Lstat(stage.target)
	if targetErr == nil && stage.info != nil && targetInfo.Mode().IsRegular() && os.SameFile(stage.info, targetInfo) {
		_ = publisher.root.Remove(stage.target)
	}
}

func (publisher *projectionPublisher) removeStageIfSame(stage rootedProjectionStage) {
	stageInfo, err := publisher.root.Lstat(stage.name)
	if err == nil && stage.info != nil && stageInfo.Mode().IsRegular() && os.SameFile(stage.info, stageInfo) {
		_ = publisher.root.Remove(stage.name)
	}
}

func (publisher *projectionPublisher) syncDirectory() error {
	directory, err := publisher.root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func projectionRandomChild(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return path.Join(".", prefix+hex.EncodeToString(random)), nil
}

func writePrivateSyncedFile(pathValue string, value []byte) error {
	file, err := os.OpenFile(pathValue, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(value)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(value) {
		return errors.New("private projection receipt write was incomplete")
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func validateDirectoryPathNoSymlinks(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	remainder := strings.TrimPrefix(absolute, volume)
	current := volume + string(os.PathSeparator)
	for _, part := range strings.Split(strings.TrimPrefix(remainder, string(os.PathSeparator)), string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink directory component is forbidden: %s", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("path component is not a directory: %s", current)
		}
	}
	return nil
}

func requireReadOnlyRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("path is not a non-symlink regular file")
	}
	if info.Mode().Perm()&0o222 != 0 {
		return fmt.Errorf("immutable object has writable mode %04o", info.Mode().Perm())
	}
	return nil
}

func syncRegularFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func stringBytesEqual(left, right []byte) bool {
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

type projectedComponent struct {
	ComponentID               string
	Ecosystem                 string
	Kind                      string
	Name                      string
	Namespace                 string
	PURL                      string
	Lifecycles                []string
	OfficialChannelRequired   bool
	OfficialChannels          []map[string]any
	ReviewedAvailableChannels int
	VersionCount              int
	OccurrenceCount           int
	SourceCount               int
	GapCount                  int
	DependencyCount           int
	DependentCount            int
}

const projectedComponentColumns = `component_id,ecosystem,kind,name,namespace,purl,lifecycles_json,
official_channel_required,official_channels_json,reviewed_available_channels,version_count,
occurrence_count,source_count,gap_count,dependency_count,dependent_count`

func scanProjectedComponent(scanner interface{ Scan(...any) error }) (*projectedComponent, error) {
	return scanProjectedComponentWithBudget(scanner, nil)
}

func scanProjectedComponentWithBudget(scanner interface{ Scan(...any) error }, budget *projectionJSONBudget) (*projectedComponent, error) {
	var component projectedComponent
	var lifecyclesRaw, channelsRaw string
	var required int
	if err := scanner.Scan(&component.ComponentID, &component.Ecosystem, &component.Kind, &component.Name,
		&component.Namespace, &component.PURL, &lifecyclesRaw, &required, &channelsRaw,
		&component.ReviewedAvailableChannels, &component.VersionCount, &component.OccurrenceCount,
		&component.SourceCount, &component.GapCount, &component.DependencyCount, &component.DependentCount); err != nil {
		return nil, err
	}
	if required != 0 && required != 1 {
		return nil, errors.New("projection contains invalid component boolean")
	}
	if err := budget.add(component.ComponentID, component.Ecosystem, component.Kind, component.Name,
		component.Namespace, component.PURL, lifecyclesRaw, channelsRaw); err != nil {
		return nil, err
	}
	component.OfficialChannelRequired = required == 1
	if err := decodeProjectionMeta(lifecyclesRaw, &component.Lifecycles); err != nil {
		return nil, err
	}
	if err := decodeProjectionMeta(channelsRaw, &component.OfficialChannels); err != nil {
		return nil, err
	}
	if len(component.Lifecycles) > maxRegistryLifecycles || len(component.OfficialChannels) > maxRegistryChannelsPerComponent {
		return nil, errors.New("projection component exceeds lifecycle or official-channel count bounds")
	}
	core := []string{component.ComponentID, component.Ecosystem, component.Kind, component.Name, component.Namespace, component.PURL}
	core = append(core, component.Lifecycles...)
	if err := validateExposedRow("projection component", core...); err != nil {
		return nil, err
	}
	for index, channel := range component.OfficialChannels {
		if err := validateLooseValue(fmt.Sprintf("projection component channel[%d]", index), channel,
			maxRegistryToolRowBytes, maxRegistryRecordNodes, maxRegistryCollectionEntries); err != nil {
			return nil, err
		}
	}
	return &component, nil
}

func projectedComponentMap(component *projectedComponent) map[string]any {
	if component == nil {
		return map[string]any{}
	}
	return map[string]any{
		"component_id":                component.ComponentID,
		"ecosystem":                   component.Ecosystem,
		"kind":                        component.Kind,
		"name":                        component.Name,
		"namespace":                   component.Namespace,
		"purl":                        component.PURL,
		"lifecycles":                  component.Lifecycles,
		"official_channel_required":   component.OfficialChannelRequired,
		"reviewed_available_channels": component.ReviewedAvailableChannels,
		"version_count":               component.VersionCount,
		"occurrence_count":            component.OccurrenceCount,
		"source_count":                component.SourceCount,
		"gap_count":                   component.GapCount,
		"dependency_count":            component.DependencyCount,
		"dependent_count":             component.DependentCount,
	}
}

func projectedAsRegistryComponent(component *projectedComponent) *registryComponent {
	return &registryComponent{
		ComponentID: component.ComponentID, Ecosystem: component.Ecosystem, Kind: component.Kind,
		Name: component.Name, Namespace: component.Namespace, PURL: component.PURL,
		Lifecycles: component.Lifecycles, OfficialChannelRequired: component.OfficialChannelRequired,
		OfficialChannels: component.OfficialChannels,
	}
}

func (projection *registryProjection) searchComponents(query, ecosystem, kind, lifecycle string, limit int) toolOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), projectionOpenTimeout)
	defer cancel()
	queryLower := strings.ToLower(strings.TrimSpace(query))
	terms, termErr := boundedSearchTerms(queryLower)
	if termErr != nil {
		return errorOutcome(stateForbidden, termErr.Error(), nil)
	}
	if len(terms) == 0 {
		return outcome(stateEmpty, map[string]any{
			"query": query, "matches": []map[string]any{}, "matched_count": 0,
			"matched_count_exact": true, "result_count": 0, "query_backend": projectionFormat,
		})
	}
	where := []string{"1=1"}
	arguments := make([]any, 0)
	sqlTerms := terms
	plan := newComponentSearchPlan(queryLower, terms)
	if ecosystem != "" {
		where = append(where, "ecosystem = ? COLLATE NOCASE")
		arguments = append(arguments, ecosystem)
	}
	if kind != "" {
		where = append(where, "kind = ? COLLATE NOCASE")
		arguments = append(arguments, kind)
	}
	for _, term := range sqlTerms {
		where = append(where, `lower(component_id || ' ' || ecosystem || ' ' || kind || ' ' || namespace || ' ' || name || ' ' || purl) LIKE ? ESCAPE '!'`)
		arguments = append(arguments, "%"+escapeLike(term)+"%")
	}
	if lifecycle != "" {
		where = append(where, `EXISTS (SELECT 1 FROM json_each(components.lifecycles_json) WHERE json_each.value = ? COLLATE NOCASE)`)
		arguments = append(arguments, lifecycle)
	}
	clause := strings.Join(where, " AND ")
	var matchedCount int
	if err := projection.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM components WHERE "+clause, arguments...).Scan(&matchedCount); err != nil {
		return errorOutcome(stateBackendUnavailable, "count compact component projection: "+err.Error(), nil)
	}
	queryArguments := append(append([]any{}, arguments...), maxProjectionSearchRows+1)
	rows, err := projection.db.QueryContext(ctx, "SELECT "+projectedComponentColumns+" FROM components WHERE "+clause+" ORDER BY component_id LIMIT ?", queryArguments...)
	if err != nil {
		return errorOutcome(stateBackendUnavailable, "query compact component projection: "+err.Error(), nil)
	}
	defer rows.Close()
	type match struct {
		component *projectedComponent
		score     int
	}
	matches := make([]match, 0, minInt(matchedCount, maxProjectionSearchRows))
	budget := newProjectionJSONBudget()
	scanTruncated := false
	budgetTruncated := false
	scannedCount := 0
	for rows.Next() {
		if scannedCount == maxProjectionSearchRows {
			scanTruncated = true
			break
		}
		component, err := scanProjectedComponentWithBudget(rows, budget)
		if errors.Is(err, errProjectionRowBudget) {
			budgetTruncated = true
			break
		}
		if err != nil {
			return errorOutcome(stateBackendUnavailable, "decode compact component projection: "+err.Error(), nil)
		}
		scannedCount++
		score := plan.score(projectedAsRegistryComponent(component))
		if score > 0 {
			matches = append(matches, match{component: component, score: score})
		}
	}
	if err := rows.Err(); err != nil {
		return errorOutcome(stateBackendUnavailable, "scan compact component projection: "+err.Error(), nil)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return componentLess(projectedAsRegistryComponent(matches[i].component), projectedAsRegistryComponent(matches[j].component))
	})
	results := make([]map[string]any, 0, minInt(limit, len(matches)))
	for _, matched := range matches[:minInt(limit, len(matches))] {
		item := projectedComponentMap(matched.component)
		item["score"] = matched.score
		results = append(results, item)
	}
	state := stateOK
	if len(results) == 0 {
		state = stateEmpty
	}
	if scanTruncated || budgetTruncated {
		state = statePartial
	}
	return outcome(state, map[string]any{
		"query": query, "matches": results, "matched_count": matchedCount,
		"matched_count_exact": true, "result_count": len(results), "query_backend": projectionFormat,
		"truncated": len(results) < matchedCount, "scan_truncated": scanTruncated,
		"row_budget_truncated": budgetTruncated, "scanned_count": scannedCount,
		"scan_limit": maxProjectionSearchRows, "row_json_bytes": budget.used,
		"row_json_byte_limit": budget.maximum,
		"ranking_complete":    !scanTruncated && !budgetTruncated,
	})
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, "!", "!!")
	value = strings.ReplaceAll(value, "%", "!%")
	return strings.ReplaceAll(value, "_", "!_")
}

func (projection *registryProjection) component(ctx context.Context, componentID string) (*projectedComponent, error) {
	return projection.componentWithBudget(ctx, componentID, nil)
}

func (projection *registryProjection) componentWithBudget(ctx context.Context, componentID string, budget *projectionJSONBudget) (*projectedComponent, error) {
	row := projection.db.QueryRowContext(ctx, "SELECT "+projectedComponentColumns+" FROM components WHERE component_id=?", componentID)
	component, err := scanProjectedComponentWithBudget(row, budget)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return component, nil
}

func (projection *registryProjection) getComponent(componentID string, limit int) toolOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), projectionOpenTimeout)
	defer cancel()
	component, err := projection.component(ctx, componentID)
	if err != nil {
		return errorOutcome(stateBackendUnavailable, "query compact component projection: "+err.Error(), nil)
	}
	if component == nil {
		return outcome(stateNotFound, map[string]any{"component_id": componentID})
	}
	rows, err := projection.db.QueryContext(ctx, `SELECT component_version_id,resolved_version,constraint_value,
source_ref,artifact_digest,platform,resolution_state,evidence_json FROM versions
WHERE component_id=? ORDER BY component_version_id LIMIT ?`, componentID, limit)
	if err != nil {
		return errorOutcome(stateBackendUnavailable, "query compact version projection: "+err.Error(), nil)
	}
	defer rows.Close()
	versions := make([]map[string]any, 0, limit)
	for rows.Next() {
		version, err := scanProjectedVersion(rows)
		if err != nil {
			return errorOutcome(stateBackendUnavailable, "decode compact version projection: "+err.Error(), nil)
		}
		versions = append(versions, versionProjection(version))
	}
	if err := rows.Err(); err != nil {
		return errorOutcome(stateBackendUnavailable, "scan compact version projection: "+err.Error(), nil)
	}
	return outcome(stateOK, map[string]any{
		"component": projectedComponentMap(component), "versions": versions,
		"versions_truncated": len(versions) < component.VersionCount,
	})
}

func scanProjectedVersion(scanner interface{ Scan(...any) error }) (registryVersion, error) {
	var version registryVersion
	var evidenceRaw string
	err := scanner.Scan(&version.ComponentVersionID, &version.ResolvedVersion, &version.Constraint,
		&version.SourceRef, &version.ArtifactDigest, &version.Platform, &version.ResolutionState, &evidenceRaw)
	if err != nil {
		return registryVersion{}, err
	}
	if err := decodeProjectionMeta(evidenceRaw, &version.Evidence); err != nil {
		return registryVersion{}, err
	}
	return version, nil
}

func (projection *registryProjection) officialChannels(componentID, channelType string, acceptedOnly bool, limit int) toolOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), projectionOpenTimeout)
	defer cancel()
	component, err := projection.component(ctx, componentID)
	if err != nil {
		return errorOutcome(stateBackendUnavailable, "query compact component projection: "+err.Error(), nil)
	}
	if component == nil {
		return outcome(stateNotFound, map[string]any{"component_id": componentID})
	}
	channels := make([]map[string]any, 0)
	for _, channel := range component.OfficialChannels {
		if channelType != "" && !strings.EqualFold(stringField(channel, "channel_type"), channelType) {
			continue
		}
		if acceptedOnly && !acceptedAvailableChannel(channel) {
			continue
		}
		channels = append(channels, channelProjection(channel))
	}
	sort.Slice(channels, func(i, j int) bool {
		return fmt.Sprint(channels[i]["channel_type"], "\x00", channels[i]["channel_id"]) < fmt.Sprint(channels[j]["channel_type"], "\x00", channels[j]["channel_id"])
	})
	total := len(channels)
	if len(channels) > limit {
		channels = channels[:limit]
	}
	state := stateOK
	if len(channels) == 0 {
		if component.OfficialChannelRequired {
			state = stateNoOfficialChannel
		} else {
			state = stateEmpty
		}
	}
	return outcome(state, map[string]any{
		"component_id": componentID, "accepted_only": acceptedOnly, "channels": channels,
		"total": total, "truncated": len(channels) < total,
	})
}

type projectedDirectedRelation struct {
	Direction string
	Relation  registryRelation
}

func (projection *registryProjection) relationships(componentID, direction, scope string, offset, limit int) toolOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), projectionOpenTimeout)
	defer cancel()
	budget := newProjectionJSONBudget()
	component, err := projection.componentWithBudget(ctx, componentID, budget)
	if err != nil {
		return errorOutcome(stateBackendUnavailable, "query compact component projection: "+err.Error(), nil)
	}
	if component == nil {
		return outcome(stateNotFound, map[string]any{"component_id": componentID})
	}
	type relationSegment struct {
		column, direction string
		total             int
	}
	segments := make([]relationSegment, 0, 2)
	if direction == "dependencies" || direction == "both" {
		total, err := projection.relationCount(ctx, "from_component_id", componentID, scope)
		if err != nil {
			return errorOutcome(stateBackendUnavailable, "count compact dependency projection: "+err.Error(), nil)
		}
		segments = append(segments, relationSegment{column: "from_component_id", direction: "dependency", total: total})
	}
	if direction == "dependents" || direction == "both" {
		total, err := projection.relationCount(ctx, "to_component_id", componentID, scope)
		if err != nil {
			return errorOutcome(stateBackendUnavailable, "count compact dependent projection: "+err.Error(), nil)
		}
		segments = append(segments, relationSegment{column: "to_component_id", direction: "dependent", total: total})
	}
	total := 0
	for _, segment := range segments {
		total += segment.total
	}
	start, _ := pageBounds(total, offset, limit)
	skip := start
	remaining := limit
	selected := make([]projectedDirectedRelation, 0, minInt(limit, total-start))
	budgetTruncated := false
	for _, segment := range segments {
		if skip >= segment.total {
			skip -= segment.total
			continue
		}
		want := minInt(remaining, segment.total-skip)
		rows, truncated, err := projection.relationRows(ctx, segment.column, componentID, segment.direction, scope, skip, want, budget)
		if err != nil {
			return errorOutcome(stateBackendUnavailable, "query compact relationship projection: "+err.Error(), nil)
		}
		selected = append(selected, rows...)
		remaining -= len(rows)
		skip = 0
		if truncated {
			budgetTruncated = true
			break
		}
		if remaining == 0 {
			break
		}
	}
	items := make([]map[string]any, 0, len(selected))
	componentCache := map[string]*projectedComponent{componentID: component}
	for _, item := range selected {
		otherID := item.Relation.ToComponentID
		if item.Direction == "dependent" {
			otherID = item.Relation.FromComponentID
		}
		other := componentCache[otherID]
		if other == nil {
			other, err = projection.componentWithBudget(ctx, otherID, budget)
			if errors.Is(err, errProjectionRowBudget) {
				budgetTruncated = true
				break
			}
			if err != nil || other == nil {
				return errorOutcome(stateBackendUnavailable, "resolve compact relationship component", map[string]any{"component_id": otherID})
			}
			componentCache[otherID] = other
		}
		items = append(items, map[string]any{
			"direction": item.Direction, "component": projectedComponentMap(other),
			"from_component_id": item.Relation.FromComponentID,
			"to_component_id":   item.Relation.ToComponentID,
			"relationship":      item.Relation.Relationship, "scope": item.Relation.Scope,
			"optional": item.Relation.Optional, "edge_count": item.Relation.EdgeCount,
			"evidence_occurrence_ids":        item.Relation.EvidenceOccurrences,
			"evidence_occurrence_count":      item.Relation.EdgeCount,
			"evidence_occurrences_truncated": len(item.Relation.EvidenceOccurrences) < item.Relation.EdgeCount,
		})
	}
	state := stateOK
	if len(items) == 0 {
		state = stateEmpty
	}
	if budgetTruncated {
		state = statePartial
	}
	next := nextOffset(start+len(items), total)
	return outcome(state, map[string]any{
		"component_id": componentID, "direction": direction, "relationships": items,
		"total": total, "total_exact": true, "offset": start, "next_offset": next,
		"truncated": next != nil, "row_budget_truncated": budgetTruncated,
		"row_json_bytes": budget.used, "row_json_byte_limit": budget.maximum,
	})
}

func (projection *registryProjection) relationCount(ctx context.Context, column, componentID, scope string) (int, error) {
	if column != "from_component_id" && column != "to_component_id" {
		return 0, errors.New("invalid relation direction column")
	}
	query := "SELECT COUNT(*) FROM relations WHERE " + column + "=?"
	arguments := []any{componentID}
	if scope != "" {
		query += " AND scope=? COLLATE NOCASE"
		arguments = append(arguments, scope)
	}
	var total int
	if err := projection.db.QueryRowContext(ctx, query, arguments...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (projection *registryProjection) relationRows(ctx context.Context, column, componentID, direction, scope string, offset, limit int, budget *projectionJSONBudget) ([]projectedDirectedRelation, bool, error) {
	if column != "from_component_id" && column != "to_component_id" {
		return nil, false, errors.New("invalid relation direction column")
	}
	query := `SELECT from_component_id,to_component_id,relationship,scope,optional,edge_count,
evidence_occurrence_ids_json FROM relations WHERE ` + column + "=?"
	arguments := []any{componentID}
	if scope != "" {
		query += " AND scope=? COLLATE NOCASE"
		arguments = append(arguments, scope)
	}
	query += " ORDER BY from_component_id,to_component_id,relationship,scope,optional LIMIT ? OFFSET ?"
	arguments = append(arguments, limit, offset)
	rows, err := projection.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	result := make([]projectedDirectedRelation, 0, limit)
	truncated := false
	for rows.Next() {
		var relation registryRelation
		var optional int
		var evidenceRaw string
		if err := rows.Scan(&relation.FromComponentID, &relation.ToComponentID, &relation.Relationship,
			&relation.Scope, &optional, &relation.EdgeCount, &evidenceRaw); err != nil {
			return nil, false, err
		}
		if optional != 0 && optional != 1 {
			return nil, false, errors.New("projection contains invalid relation boolean")
		}
		relation.Optional = optional == 1
		if err := budget.add(relation.FromComponentID, relation.ToComponentID, relation.Relationship,
			relation.Scope, evidenceRaw); errors.Is(err, errProjectionRowBudget) {
			truncated = true
			break
		} else if err != nil {
			return nil, false, err
		}
		if err := decodeProjectionMeta(evidenceRaw, &relation.EvidenceOccurrences); err != nil {
			return nil, false, err
		}
		if len(relation.EvidenceOccurrences) > 8 {
			return nil, false, errors.New("projection relation exceeds evidence occurrence ID bound")
		}
		result = append(result, projectedDirectedRelation{Direction: direction, Relation: relation})
	}
	return result, truncated, rows.Err()
}

func (projection *registryProjection) evidence(componentID, kind, gapType string, offset, limit int) toolOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), projectionOpenTimeout)
	defer cancel()
	if componentID != "" {
		component, err := projection.component(ctx, componentID)
		if err != nil {
			return errorOutcome(stateBackendUnavailable, "query compact component projection: "+err.Error(), nil)
		}
		if component == nil {
			return outcome(stateNotFound, map[string]any{"component_id": componentID})
		}
	}
	items := make([]map[string]any, 0, limit)
	total := 0
	pageOffset := offset
	var err error
	switch kind {
	case "gaps":
		items, total, pageOffset, err = projection.gapEvidence(ctx, componentID, gapType, offset, limit)
	case "occurrences":
		items, total, pageOffset, err = projection.occurrenceEvidence(ctx, componentID, offset, limit)
	case "sources":
		items, total, pageOffset, err = projection.sourceEvidence(ctx, componentID, offset, limit)
	case "versions":
		items, total, pageOffset, err = projection.versionEvidence(ctx, componentID, offset, limit)
	}
	if err != nil {
		return errorOutcome(stateBackendUnavailable, "query compact evidence projection: "+err.Error(), nil)
	}
	state := stateOK
	if len(items) == 0 {
		state = stateEmpty
	}
	return outcome(state, map[string]any{
		"component_id": nullableString(componentID), "kind": kind, "items": items,
		"total": total, "offset": pageOffset, "next_offset": nextOffset(pageOffset+len(items), total),
	})
}

func (projection *registryProjection) gapEvidence(ctx context.Context, componentID, gapType string, offset, limit int) ([]map[string]any, int, int, error) {
	where := []string{"1=1"}
	arguments := make([]any, 0, 4)
	if componentID != "" {
		where = append(where, "component_id=?")
		arguments = append(arguments, componentID)
	}
	if gapType != "" {
		where = append(where, "gap_type=? COLLATE NOCASE")
		arguments = append(arguments, gapType)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := projection.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM gaps WHERE "+clause, arguments...).Scan(&total); err != nil {
		return nil, 0, 0, err
	}
	start, _ := pageBounds(total, offset, limit)
	queryArguments := append(append([]any{}, arguments...), limit, start)
	rows, err := projection.db.QueryContext(ctx, `SELECT gap_id,gap_type,component_id,component_version_id,
source_id,message,evidence_json FROM gaps WHERE `+clause+` ORDER BY gap_id LIMIT ? OFFSET ?`, queryArguments...)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0, limit)
	for rows.Next() {
		var gap registryGap
		var evidenceRaw string
		if err := rows.Scan(&gap.GapID, &gap.GapType, &gap.ComponentID, &gap.ComponentVersionID,
			&gap.SourceID, &gap.Message, &evidenceRaw); err != nil {
			return nil, 0, 0, err
		}
		if err := decodeProjectionMeta(evidenceRaw, &gap.Evidence); err != nil {
			return nil, 0, 0, err
		}
		items = append(items, gapProjection(gap))
	}
	return items, total, start, rows.Err()
}

func (projection *registryProjection) versionEvidence(ctx context.Context, componentID string, offset, limit int) ([]map[string]any, int, int, error) {
	var total int
	if err := projection.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM versions WHERE component_id=?", componentID).Scan(&total); err != nil {
		return nil, 0, 0, err
	}
	start, _ := pageBounds(total, offset, limit)
	rows, err := projection.db.QueryContext(ctx, `SELECT component_version_id,resolved_version,constraint_value,
source_ref,artifact_digest,platform,resolution_state,evidence_json FROM versions
WHERE component_id=? ORDER BY component_version_id LIMIT ? OFFSET ?`, componentID, limit, start)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0, limit)
	for rows.Next() {
		version, err := scanProjectedVersion(rows)
		if err != nil {
			return nil, 0, 0, err
		}
		items = append(items, versionProjection(version))
	}
	return items, total, start, rows.Err()
}

func (projection *registryProjection) occurrenceEvidence(ctx context.Context, componentID string, offset, limit int) ([]map[string]any, int, int, error) {
	var total int
	if err := projection.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM occurrences WHERE component_id=?", componentID).Scan(&total); err != nil {
		return nil, 0, 0, err
	}
	start, _ := pageBounds(total, offset, limit)
	rows, err := projection.db.QueryContext(ctx, `SELECT o.occurrence_id,o.component_version_id,o.source_id,
o.root_id,o.lifecycle,o.role,o.dependency_scope,o.directness,o.optional,o.evidence_locator,o.raw_value,
s.source_type,s.evidence_uri,s.content_hash FROM occurrences o JOIN sources s ON s.source_id=o.source_id
WHERE o.component_id=? ORDER BY o.occurrence_id LIMIT ? OFFSET ?`, componentID, limit, start)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0, limit)
	for rows.Next() {
		var occurrence registryOccurrence
		var source registrySource
		var optional int
		if err := rows.Scan(&occurrence.OccurrenceID, &occurrence.ComponentVersionID, &occurrence.SourceID,
			&occurrence.RootID, &occurrence.Lifecycle, &occurrence.Role, &occurrence.DependencyScope,
			&occurrence.Directness, &optional, &occurrence.EvidenceLocator, &occurrence.RawValue,
			&source.SourceType, &source.EvidenceURI, &source.ContentHash); err != nil {
			return nil, 0, 0, err
		}
		if optional != 0 && optional != 1 {
			return nil, 0, 0, errors.New("projection contains invalid occurrence boolean")
		}
		occurrence.Optional = optional == 1
		source.SourceID = occurrence.SourceID
		item := map[string]any{
			"occurrence_id":        occurrence.OccurrenceID,
			"component_version_id": occurrence.ComponentVersionID,
			"source_id":            occurrence.SourceID, "root_id": occurrence.RootID,
			"lifecycle": occurrence.Lifecycle, "role": occurrence.Role,
			"dependency_scope": occurrence.DependencyScope, "directness": occurrence.Directness,
			"optional":         occurrence.Optional,
			"evidence_locator": boundString(occurrence.EvidenceLocator, 2048),
			"raw_value":        boundString(occurrence.RawValue, 2048), "source": sourceProjection(source),
		}
		items = append(items, item)
	}
	return items, total, start, rows.Err()
}

func (projection *registryProjection) sourceEvidence(ctx context.Context, componentID string, offset, limit int) ([]map[string]any, int, int, error) {
	var total int
	if err := projection.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM component_sources WHERE component_id=?", componentID).Scan(&total); err != nil {
		return nil, 0, 0, err
	}
	start, _ := pageBounds(total, offset, limit)
	rows, err := projection.db.QueryContext(ctx, `SELECT s.source_id,s.source_type,s.evidence_uri,s.content_hash
FROM component_sources cs JOIN sources s ON s.source_id=cs.source_id WHERE cs.component_id=?
ORDER BY s.source_id LIMIT ? OFFSET ?`, componentID, limit, start)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0, limit)
	for rows.Next() {
		var source registrySource
		if err := rows.Scan(&source.SourceID, &source.SourceType, &source.EvidenceURI, &source.ContentHash); err != nil {
			return nil, 0, 0, err
		}
		items = append(items, sourceProjection(source))
	}
	return items, total, start, rows.Err()
}

func (projection *registryProjection) gapTypes(limit int) ([]map[string]any, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), projectionOpenTimeout)
	defer cancel()
	var total int
	if err := projection.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM (SELECT 1 FROM gaps GROUP BY gap_type)").Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := projection.db.QueryContext(ctx,
		"SELECT gap_type,COUNT(*) FROM gaps GROUP BY gap_type ORDER BY gap_type LIMIT ?", limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := make([]map[string]any, 0, minInt(limit, total))
	for rows.Next() {
		var gapType string
		var count int
		if err := rows.Scan(&gapType, &count); err != nil {
			return nil, 0, err
		}
		if len(gapType) > maxRegistryGapTypeBytes {
			return nil, 0, fmt.Errorf("projection gap type exceeds %d-byte bound", maxRegistryGapTypeBytes)
		}
		result = append(result, map[string]any{"gap_type": gapType, "count": count})
	}
	return result, total, rows.Err()
}

func (projection *registryProjection) close() error {
	if projection == nil || projection.db == nil {
		return nil
	}
	return projection.db.Close()
}
