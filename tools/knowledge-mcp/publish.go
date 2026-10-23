package main

// Cluster-side publisher for the signed generation store and the retrieval
// federation tree.
//
// The publisher runs the broker's OWN verification code (newRegistryProvider /
// loadRetrievalCatalog) rather than a reimplementation, so "the publisher
// accepted it" and "the broker accepts it" cannot drift apart. Two modes:
//
//	--publish-pack <store-dir>        workstation: verify, then emit a bundle
//	--publish-materialize <src>       cluster initContainer: verify, then place
//
// Trust boundary: the transport is untrusted. Integrity rests on (1) the
// operator's whole-bundle SHA-256 pin, (2) the per-entry digests in the
// in-bundle manifest, and (3) the SSHSIG verification the broker performs
// against an allowed-signers trust root that travels through Git, never
// through the bundle. A bundle can therefore be served over plain HTTP from
// object storage without making that storage part of the trusted computing
// base.

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	publishStateDirName     = "state"
	publishTrustDirName     = "trust"
	publishRetrievalDirName = "retrieval"
	publishTrustFileName    = "knowledge-registry.allowed_signers"
	publishStatusFileName   = "publish-status.json"
	publishStagingDirName   = ".staging"
	publishManifestName     = "bundle.json"
	publishPointerFileName  = "generation-pointer.json"

	publishBundleSchemaVersion = "1.0.0"
	publishBundleRecordKind    = "knowledge_store_publication_bundle"

	publishMaxBundleBytes   int64 = 8 << 30
	publishMaxManifestBytes int64 = 64 << 20
	publishMaxEntries             = 1 << 17
	publishFetchTimeout           = 30 * time.Minute

	publishFileMode      os.FileMode = 0o444
	publishDirMode       os.FileMode = 0o755
	publishSealedDirMode os.FileMode = 0o555
)

var (
	publishStoreSubdirectories = []string{"manifests", "pointers", "receipts", "policies"}
	publishPolicyNamePattern   = regexp.MustCompile(`^[0-9a-f]{64}\.allowed_signers$`)
	publishPathSegmentPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// emitPublishRecord prints the receipt on stdout; publish modes never speak
// JSON-RPC, so stdout is free for the operator's pin.
func emitPublishRecord(record *publishStatus) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(record)
}

// validatePublishConfig enforces the two publish modes and reports whether one
// of them is active. Publish modes are mutually exclusive with each other and
// with every serving input, so one process is either a broker or a publisher —
// never both.
func validatePublishConfig(values *config, configuredInputs int) (bool, error) {
	packing := values.publishPack != ""
	materializing := values.publishMaterialize != ""
	if !packing && !materializing {
		for label, value := range map[string]string{
			"--publish-output":       values.publishOutput,
			"--publish-retrieval":    values.publishRetrieval,
			"--publish-sha256":       values.publishSHA256,
			"--publish-target":       values.publishTarget,
			"--publish-trust-source": values.publishTrustSource,
		} {
			if value != "" {
				return false, fmt.Errorf("%s requires --publish-pack or --publish-materialize", label)
			}
		}
		return false, nil
	}
	if packing && materializing {
		return false, errors.New("--publish-pack and --publish-materialize are mutually exclusive")
	}
	if configuredInputs != 0 || values.compileManifest != "" || values.sdkTransport || values.httpBind != "" {
		return false, errors.New("publish modes cannot be combined with serving or projection-compilation inputs")
	}

	if packing {
		if values.publishOutput == "" {
			return false, errors.New("--publish-pack requires --publish-output")
		}
		if values.allowedSigners == "" {
			return false, errors.New("--publish-pack requires an external --allowed-signers trust root")
		}
		if values.publishSHA256 != "" || values.publishTarget != "" || values.publishTrustSource != "" {
			return false, errors.New("--publish-sha256, --publish-target and --publish-trust-source belong to --publish-materialize")
		}
		return true, resolvePublishPaths(values,
			&values.publishPack, &values.publishOutput, &values.publishRetrieval, &values.allowedSigners)
	}

	if !validSHA256Hex(values.publishSHA256) {
		return false, errors.New("--publish-materialize requires a 64-lowercase-hex --publish-sha256 pin")
	}
	if values.publishTarget == "" {
		return false, errors.New("--publish-materialize requires --publish-target")
	}
	if values.publishTrustSource == "" {
		return false, errors.New("--publish-materialize requires --publish-trust-source")
	}
	if values.publishOutput != "" || values.publishRetrieval != "" {
		return false, errors.New("--publish-output and --publish-retrieval belong to --publish-pack")
	}
	return true, resolvePublishPaths(values, &values.publishTarget, &values.publishTrustSource)
}

func resolvePublishPaths(values *config, targets ...*string) error {
	for _, target := range targets {
		if *target == "" {
			continue
		}
		absolute, err := filepath.Abs(*target)
		if err != nil {
			return fmt.Errorf("resolve publish path %q: %w", *target, err)
		}
		*target = filepath.Clean(absolute)
	}
	if values.publishMaterialize != "" {
		parsed, err := url.Parse(values.publishMaterialize)
		if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
			return nil
		}
		absolute, err := filepath.Abs(values.publishMaterialize)
		if err != nil {
			return fmt.Errorf("resolve bundle source: %w", err)
		}
		values.publishMaterialize = filepath.Clean(absolute)
	}
	return nil
}

// publishBundleEntry binds one payload path to its exact bytes.
type publishBundleEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// publishBundleManifest is the first tar entry. It is itself covered by the
// operator's whole-bundle pin, so it cannot be swapped independently.
type publishBundleManifest struct {
	SchemaVersion     string               `json:"schema_version"`
	RecordKind        string               `json:"record_kind"`
	PointerID         string               `json:"pointer_id"`
	CurrentManifestID string               `json:"current_manifest_id"`
	RetrievalIncluded bool                 `json:"retrieval_included"`
	Entries           []publishBundleEntry `json:"entries"`
}

// publishStatus is written to the target root on every run, successful or not,
// so a degraded publish is observable rather than a silent empty directory.
type publishStatus struct {
	SchemaVersion     string `json:"schema_version"`
	RecordKind        string `json:"record_kind"`
	State             string `json:"state"`
	Reason            string `json:"reason,omitempty"`
	BundleSHA256      string `json:"bundle_sha256,omitempty"`
	PointerID         string `json:"pointer_id,omitempty"`
	CurrentManifestID string `json:"current_manifest_id,omitempty"`
	RetrievalState    string `json:"retrieval_state,omitempty"`
	PublisherVersion  string `json:"publisher_version"`
}

// packPublishBundle verifies a workstation-local generation store with the
// broker's verifier and, only if it is fully signed and promotable, writes a
// deterministic bundle. Identical store contents always produce identical
// bundle bytes, so the SHA-256 pin is reproducible.
func packPublishBundle(configuration config) (*publishStatus, error) {
	storeRoot, err := filepath.Abs(configuration.publishPack)
	if err != nil {
		return nil, fmt.Errorf("resolve publish source: %w", err)
	}
	snapshot := newRegistryProvider(config{
		stateDirectory:  storeRoot,
		allowedSigners:  configuration.allowedSigners,
		maxRegistrySize: configuration.maxRegistrySize,
	}).snapshot()
	if snapshot.state != stateOK || snapshot.pointer == nil || snapshot.current == nil {
		return nil, fmt.Errorf("refusing to publish an unverified generation store: %s", snapshot.message)
	}

	entries, sources, err := collectStorePayload(storeRoot)
	if err != nil {
		return nil, err
	}
	if configuration.publishRetrieval != "" {
		retrievalRoot, absErr := filepath.Abs(configuration.publishRetrieval)
		if absErr != nil {
			return nil, fmt.Errorf("resolve retrieval source: %w", absErr)
		}
		retrievalEntries, retrievalSources, walkErr := collectRetrievalPayload(retrievalRoot)
		if walkErr != nil {
			return nil, walkErr
		}
		entries = append(entries, retrievalEntries...)
		for key, value := range retrievalSources {
			sources[key] = value
		}
	}
	if len(entries) > publishMaxEntries {
		return nil, fmt.Errorf("bundle holds %d entries, above the %d ceiling", len(entries), publishMaxEntries)
	}
	sort.Slice(entries, func(first, second int) bool { return entries[first].Path < entries[second].Path })

	manifest := publishBundleManifest{
		SchemaVersion:     publishBundleSchemaVersion,
		RecordKind:        publishBundleRecordKind,
		PointerID:         snapshot.pointer.PointerID,
		CurrentManifestID: snapshot.pointer.CurrentManifestID,
		RetrievalIncluded: configuration.publishRetrieval != "",
		Entries:           entries,
	}
	digest, err := writePublishBundle(configuration.publishOutput, manifest, sources)
	if err != nil {
		return nil, err
	}
	return &publishStatus{
		SchemaVersion:     publishBundleSchemaVersion,
		RecordKind:        "knowledge_store_publication_receipt",
		State:             "packed",
		BundleSHA256:      digest,
		PointerID:         snapshot.pointer.PointerID,
		CurrentManifestID: snapshot.pointer.CurrentManifestID,
		PublisherVersion:  serverVersion,
	}, nil
}

// collectStorePayload enumerates exactly the layout documented in
// tools/knowledge-mcp/README.md "generation store reader expects". Anything
// else inside the four content-addressed directories is a hard error: an
// unrecognised object in a signed store is a smuggling attempt, not noise.
func collectStorePayload(storeRoot string) ([]publishBundleEntry, map[string]string, error) {
	sources := make(map[string]string)
	entries := make([]publishBundleEntry, 0, 64)

	pointerSource := filepath.Join(storeRoot, publishPointerFileName)
	entry, err := describePayloadFile(pointerSource, path.Join(publishStateDirName, publishPointerFileName))
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", publishPointerFileName, err)
	}
	entries = append(entries, entry)
	sources[entry.Path] = pointerSource

	for _, subdirectory := range publishStoreSubdirectories {
		directory := filepath.Join(storeRoot, subdirectory)
		names, readErr := os.ReadDir(directory)
		if readErr != nil {
			return nil, nil, fmt.Errorf("read %s: %w", subdirectory, readErr)
		}
		for _, name := range names {
			if !name.Type().IsRegular() {
				return nil, nil, fmt.Errorf("%s/%s is not a regular file", subdirectory, name.Name())
			}
			if err := validateStoreObjectName(subdirectory, name.Name()); err != nil {
				return nil, nil, err
			}
			source := filepath.Join(directory, name.Name())
			entry, err := describePayloadFile(source, path.Join(publishStateDirName, subdirectory, name.Name()))
			if err != nil {
				return nil, nil, fmt.Errorf("read %s/%s: %w", subdirectory, name.Name(), err)
			}
			if subdirectory == "policies" && entry.SHA256 != strings.TrimSuffix(name.Name(), ".allowed_signers") {
				return nil, nil, fmt.Errorf("policy %s is not content-addressed by its own bytes", name.Name())
			}
			entries = append(entries, entry)
			sources[entry.Path] = source
		}
	}
	return entries, sources, nil
}

func validateStoreObjectName(subdirectory, name string) error {
	stem := strings.TrimSuffix(name, ".json")
	switch subdirectory {
	case "manifests":
		if stem != name && manifestIDPattern.MatchString(stem) {
			return nil
		}
	case "pointers":
		if stem != name && pointerIDPattern.MatchString(stem) {
			return nil
		}
	case "receipts":
		if stem != name && receiptIDPattern.MatchString(stem) {
			return nil
		}
	case "policies":
		if publishPolicyNamePattern.MatchString(name) {
			return nil
		}
	}
	return fmt.Errorf("%s/%s is not a valid content-addressed object name", subdirectory, name)
}

// collectRetrievalPayload walks the retrieval federation tree verbatim. Its
// integrity rests on the operator's catalog and executable SHA-256 pins, which
// the broker re-checks at query time.
func collectRetrievalPayload(retrievalRoot string) ([]publishBundleEntry, map[string]string, error) {
	sources := make(map[string]string)
	entries := make([]publishBundleEntry, 0, 64)
	err := filepath.WalkDir(retrievalRoot, func(current string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() {
			return nil
		}
		if !item.Type().IsRegular() {
			return fmt.Errorf("retrieval tree holds a non-regular file: %s", current)
		}
		relative, relErr := filepath.Rel(retrievalRoot, current)
		if relErr != nil {
			return relErr
		}
		bundlePath := path.Join(publishRetrievalDirName, filepath.ToSlash(relative))
		if err := validateBundlePath(bundlePath); err != nil {
			return err
		}
		entry, describeErr := describePayloadFile(current, bundlePath)
		if describeErr != nil {
			return describeErr
		}
		entries = append(entries, entry)
		sources[bundlePath] = current
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("walk retrieval tree: %w", err)
	}
	return entries, sources, nil
}

func describePayloadFile(source, bundlePath string) (publishBundleEntry, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return publishBundleEntry{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return publishBundleEntry{}, errors.New("payload object is not a non-symlink regular file")
	}
	digest, size, err := hashRegularFile(source)
	if err != nil {
		return publishBundleEntry{}, err
	}
	if size != info.Size() {
		return publishBundleEntry{}, errors.New("payload object changed while it was hashed")
	}
	return publishBundleEntry{Path: bundlePath, SHA256: digest, Size: size}, nil
}

func hashRegularFile(source string) (string, int64, error) {
	file, err := os.Open(source) // #nosec G304 -- path comes from the operator publish configuration or the validated bundle entry and private staging directory.
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, io.LimitReader(file, publishMaxBundleBytes+1))
	if err != nil {
		return "", 0, err
	}
	if size > publishMaxBundleBytes {
		return "", 0, fmt.Errorf("payload object exceeds the %d-byte ceiling", publishMaxBundleBytes)
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

// writePublishBundle emits a deterministic tar: entries sorted by path, zeroed
// timestamps and ownership, fixed modes. No compression — the payload is
// already-hashed JSON and binaries, and a deterministic tar keeps the pin
// reproducible from the store alone.
func writePublishBundle(output string, manifest publishBundleManifest, sources map[string]string) (string, error) {
	if err := validateDirectoryPathNoSymlinks(filepath.Dir(output)); err != nil {
		return "", fmt.Errorf("validate bundle output parent: %w", err)
	}
	temporary := output + ".partial"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0o600) // #nosec G304 -- operator-selected output parent was validated above; exclusive creation rejects an existing symlink.
	if err != nil {
		return "", fmt.Errorf("create bundle: %w", err)
	}
	digest := sha256.New()
	writer := tar.NewWriter(io.MultiWriter(file, digest))
	if err := writeBundleEntries(writer, manifest, sources); err != nil {
		return "", removeFileError(joinCloseError(err, file), temporary)
	}
	if err := writer.Close(); err != nil {
		return "", removeFileError(joinCloseError(err, file), temporary)
	}
	if err := file.Sync(); err != nil {
		return "", removeFileError(joinCloseError(err, file), temporary)
	}
	if err := file.Close(); err != nil {
		return "", removeFileError(err, temporary)
	}
	if err := os.Chmod(temporary, publishFileMode); err != nil {
		return "", removeFileError(err, temporary)
	}
	if err := os.Rename(temporary, output); err != nil {
		return "", removeFileError(err, temporary)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func writeBundleEntries(writer *tar.Writer, manifest publishBundleManifest, sources map[string]string) error {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := writeBundleHeader(writer, publishManifestName, int64(len(encoded))); err != nil {
		return err
	}
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	for _, entry := range manifest.Entries {
		source, ok := sources[entry.Path]
		if !ok {
			return fmt.Errorf("bundle entry %q has no source file", entry.Path)
		}
		if err := writeBundleHeader(writer, entry.Path, entry.Size); err != nil {
			return err
		}
		if err := copyBundlePayload(writer, source, entry); err != nil {
			return err
		}
	}
	return nil
}

func writeBundleHeader(writer *tar.Writer, name string, size int64) error {
	return writer.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     size,
		Mode:     int64(publishFileMode),
		Uid:      0,
		Gid:      0,
		Format:   tar.FormatPAX,
	})
}

func copyBundlePayload(writer io.Writer, source string, entry publishBundleEntry) error {
	file, err := os.Open(source) // #nosec G304 -- path comes from the operator publish configuration or the validated bundle entry and private staging directory.
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(writer, digest), io.LimitReader(file, entry.Size))
	if err != nil {
		return err
	}
	if written != entry.Size || hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("payload %q changed between hashing and packing", entry.Path)
	}
	return nil
}

// materializePublishBundle is the in-cluster half. It never leaves an
// unverified tree where the broker can read it: everything is built under a
// staging directory, verified with the broker's own verifier, and only then
// moved into place. Any failure removes the target trees entirely, so the
// broker falls back to a typed backend_unavailable/degraded state rather than
// to an unsigned path.
func materializePublishBundle(configuration config) (status *publishStatus, err error) {
	target, err := filepath.Abs(configuration.publishTarget)
	if err != nil {
		return nil, fmt.Errorf("resolve publish target: %w", err)
	}
	staging := filepath.Join(target, publishStagingDirName)
	defer func() { err = finishPublishMaterialization(target, staging, status, err, os.RemoveAll) }()
	if err := preparePublishTarget(target, staging); err != nil {
		return nil, err
	}
	manifest, digest, err := fetchAndExtractPublishBundle(configuration, staging)
	if err != nil {
		return nil, err
	}
	payload := filepath.Join(staging, "payload")
	snapshot, err := verifyPublishPayload(configuration, payload, manifest)
	if err != nil {
		return nil, err
	}
	status = &publishStatus{
		SchemaVersion: publishBundleSchemaVersion,
		RecordKind:    "knowledge_store_publication_status", State: "published",
		BundleSHA256: digest, PointerID: snapshot.pointer.PointerID,
		CurrentManifestID: snapshot.pointer.CurrentManifestID, PublisherVersion: serverVersion,
	}
	if err := placePublishPayload(configuration, payload, target, status); err != nil {
		return nil, err
	}
	return status, nil
}

func finishPublishMaterialization(target, staging string, status *publishStatus, cause error, cleanup func(string) error) error {
	cause = errors.Join(cause, cleanup(staging))
	if cause != nil {
		cause = errors.Join(cause, clearPublishedTrees(target))
	}
	if err := writePublishStatus(target, status, cause); err != nil {
		return errors.Join(cause, err, clearPublishedTrees(target))
	}
	return cause
}

func preparePublishTarget(target, staging string) error {
	if err := os.MkdirAll(target, publishDirMode); err != nil {
		return fmt.Errorf("create publish target: %w", err)
	}
	if err := clearPublishedTrees(target); err != nil {
		return err
	}
	if err := os.RemoveAll(staging); err != nil {
		return err
	}
	return os.MkdirAll(staging, publishDirMode)
}

func fetchAndExtractPublishBundle(configuration config, staging string) (*publishBundleManifest, string, error) {
	bundlePath := filepath.Join(staging, "bundle.tar")
	digest, err := fetchPublishBundle(configuration.publishMaterialize, bundlePath)
	if err != nil {
		return nil, "", fmt.Errorf("fetch bundle: %w", err)
	}
	if digest != configuration.publishSHA256 {
		return nil, "", fmt.Errorf("bundle SHA-256 %s does not match the operator pin %s", digest, configuration.publishSHA256)
	}
	manifest, err := extractPublishBundle(bundlePath, filepath.Join(staging, "payload"))
	if err != nil {
		return nil, "", fmt.Errorf("extract bundle: %w", err)
	}
	return manifest, digest, nil
}

func verifyPublishPayload(configuration config, payload string, manifest *publishBundleManifest) (*registrySnapshot, error) {
	trustDirectory := filepath.Join(payload, publishTrustDirName)
	if err := materializeTrustRoot(configuration.publishTrustSource, trustDirectory); err != nil {
		return nil, fmt.Errorf("materialize trust root: %w", err)
	}
	snapshot := newRegistryProvider(config{
		stateDirectory:  filepath.Join(payload, publishStateDirName),
		allowedSigners:  filepath.Join(trustDirectory, publishTrustFileName),
		maxRegistrySize: configuration.maxRegistrySize,
	}).snapshot()
	if snapshot.state != stateOK || snapshot.pointer == nil {
		return nil, fmt.Errorf("staged generation store failed verification: %s", snapshot.message)
	}
	if snapshot.pointer.PointerID != manifest.PointerID || snapshot.pointer.CurrentManifestID != manifest.CurrentManifestID {
		return nil, errors.New("staged generation store does not match the bundle manifest binding")
	}
	return snapshot, nil
}

func placePublishPayload(configuration config, payload, target string, status *publishStatus) error {
	for _, name := range []string{publishStateDirName, publishTrustDirName} {
		if err := os.Rename(filepath.Join(payload, name), filepath.Join(target, name)); err != nil {
			return fmt.Errorf("place %s: %w", name, err)
		}
	}
	stagedRetrieval := filepath.Join(payload, publishRetrievalDirName)
	if _, statErr := os.Stat(stagedRetrieval); statErr == nil {
		status.RetrievalState = placeRetrievalTree(configuration, stagedRetrieval, target)
	}
	for _, name := range []string{publishStateDirName, publishTrustDirName} {
		if err := sealDirectoryTree(filepath.Join(target, name)); err != nil {
			return err
		}
	}
	return nil
}

// placeRetrievalTree moves the retrieval tree to its final path and only then
// runs the broker's catalog loader, because the catalog pins absolute
// in-cluster paths that do not exist under staging. A catalog that fails to
// load takes the whole retrieval tree back out, leaving the broker to report a
// typed degraded federation rather than serving unpinned lanes.
func placeRetrievalTree(configuration config, stagedRetrieval, target string) string {
	final := filepath.Join(target, publishRetrievalDirName)
	if err := os.Rename(stagedRetrieval, final); err != nil {
		return "unavailable: place retrieval tree: " + err.Error()
	}
	if err := sealDirectoryTree(final); err != nil {
		return "unavailable: seal retrieval tree: " + err.Error()
	}
	if configuration.retrievalCatalog == "" || configuration.retrievalCatalogHash == "" {
		return "published_unverified: no catalog pin was configured"
	}
	provider := newRetrievalProvider(config{
		retrievalCatalog:     configuration.retrievalCatalog,
		retrievalCatalogHash: configuration.retrievalCatalogHash,
	})
	if _, err := provider.loadRetrievalCatalog(); err != nil {
		failure := errors.Join(err, os.RemoveAll(final))
		return "unavailable: catalog verification failed: " + failure.Error()
	}
	return "published"
}

func clearPublishedTrees(target string) error {
	var failure error
	for _, name := range []string{publishStateDirName, publishTrustDirName, publishRetrievalDirName} {
		path := filepath.Join(target, name)
		failure = errors.Join(failure, unsealDirectoryTree(path), os.RemoveAll(path))
	}
	return failure
}

// fetchPublishBundle accepts a local path or an http(s) URL. The transport is
// deliberately untrusted: the caller compares the returned digest with the
// operator pin before a single byte is extracted.
func fetchPublishBundle(source, destination string) (string, error) {
	parsed, err := url.Parse(source)
	if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		return downloadPublishBundle(source, destination)
	}
	absolute, err := filepath.Abs(source)
	if err != nil {
		return "", err
	}
	file, err := os.Open(absolute) // #nosec G304 -- path comes from the operator publish configuration or the validated bundle entry and private staging directory.
	if err != nil {
		return "", err
	}
	defer file.Close()
	return streamToFile(file, destination)
}

func downloadPublishBundle(source, destination string) (string, error) {
	client := &http.Client{Timeout: publishFetchTimeout}
	response, err := client.Get(source)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bundle endpoint returned HTTP %d", response.StatusCode)
	}
	return streamToFile(response.Body, destination)
}

func streamToFile(reader io.Reader, destination string) (string, error) {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0o600) // #nosec G304 -- path comes from the operator publish configuration or the validated bundle entry and private staging directory.
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, digest), io.LimitReader(reader, publishMaxBundleBytes+1))
	if err != nil {
		return "", err
	}
	if written > publishMaxBundleBytes {
		return "", fmt.Errorf("bundle exceeds the %d-byte ceiling", publishMaxBundleBytes)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// extractPublishBundle unpacks into an empty staging tree. Only regular files
// under state/ and retrieval/ are accepted; trust/ is refused outright so a
// bundle can never supply the trust root that authorises it.
func extractPublishBundle(bundlePath, payload string) (*publishBundleManifest, error) {
	file, err := os.Open(bundlePath) // #nosec G304 -- path comes from the operator publish configuration or the validated bundle entry and private staging directory.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := os.MkdirAll(payload, publishDirMode); err != nil {
		return nil, err
	}
	reader := tar.NewReader(file)

	manifest, err := readBundleManifest(reader)
	if err != nil {
		return nil, err
	}
	expected := make(map[string]publishBundleEntry, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if err := validateBundlePath(entry.Path); err != nil {
			return nil, err
		}
		if !validSHA256Hex(entry.SHA256) || entry.Size < 0 {
			return nil, fmt.Errorf("bundle manifest entry %q has an invalid digest or size", entry.Path)
		}
		if _, duplicate := expected[entry.Path]; duplicate {
			return nil, fmt.Errorf("bundle manifest lists %q twice", entry.Path)
		}
		expected[entry.Path] = entry
	}

	seen := make(map[string]struct{}, len(expected))
	for count := 0; ; count++ {
		header, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
		if count >= publishMaxEntries {
			return nil, fmt.Errorf("bundle holds more than %d entries", publishMaxEntries)
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("bundle entry %q is not a regular file", header.Name)
		}
		entry, known := expected[header.Name]
		if !known {
			return nil, fmt.Errorf("bundle entry %q is not covered by the bundle manifest", header.Name)
		}
		if _, duplicate := seen[header.Name]; duplicate {
			return nil, fmt.Errorf("bundle holds %q twice", header.Name)
		}
		if header.Size != entry.Size {
			return nil, fmt.Errorf("bundle entry %q has size %d, manifest says %d", header.Name, header.Size, entry.Size)
		}
		if err := extractBundleEntry(reader, payload, entry); err != nil {
			return nil, err
		}
		seen[header.Name] = struct{}{}
	}
	if len(seen) != len(expected) {
		for name := range expected {
			if _, ok := seen[name]; !ok {
				return nil, fmt.Errorf("bundle manifest entry %q is missing from the bundle", name)
			}
		}
	}
	if _, ok := seen[path.Join(publishStateDirName, publishPointerFileName)]; !ok {
		return nil, errors.New("bundle holds no generation pointer")
	}
	return manifest, nil
}

func readBundleManifest(reader *tar.Reader) (*publishBundleManifest, error) {
	header, err := reader.Next()
	if err != nil {
		return nil, fmt.Errorf("read bundle manifest header: %w", err)
	}
	if header.Name != publishManifestName || header.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("bundle does not start with a %s regular file", publishManifestName)
	}
	if header.Size > publishMaxManifestBytes {
		return nil, fmt.Errorf("bundle manifest exceeds the %d-byte ceiling", publishMaxManifestBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(reader, publishMaxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != header.Size {
		return nil, errors.New("bundle manifest size does not match its header")
	}
	var manifest publishBundleManifest
	if err := decodeStrictTyped(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode bundle manifest: %w", err)
	}
	if manifest.SchemaVersion != publishBundleSchemaVersion || manifest.RecordKind != publishBundleRecordKind {
		return nil, errors.New("bundle manifest schema_version or record_kind is unsupported")
	}
	if !pointerIDPattern.MatchString(manifest.PointerID) || !manifestIDPattern.MatchString(manifest.CurrentManifestID) {
		return nil, errors.New("bundle manifest pointer or manifest identity is invalid")
	}
	if len(manifest.Entries) == 0 || len(manifest.Entries) > publishMaxEntries {
		return nil, errors.New("bundle manifest entry count is out of range")
	}
	return &manifest, nil
}

func extractBundleEntry(reader io.Reader, payload string, entry publishBundleEntry) error {
	destination := filepath.Join(payload, filepath.FromSlash(entry.Path))
	if err := os.MkdirAll(filepath.Dir(destination), publishDirMode); err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path comes from the operator publish configuration or the validated bundle entry and private staging directory.
	if err != nil {
		return err
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, digest), io.LimitReader(reader, entry.Size+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != entry.Size {
		return fmt.Errorf("bundle entry %q holds %d bytes, manifest says %d", entry.Path, written, entry.Size)
	}
	if hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("bundle entry %q does not match its manifest digest", entry.Path)
	}
	return os.Chmod(destination, publishFileMode)
}

// validateBundlePath refuses traversal, absolute paths, non-canonical paths and
// any top-level directory other than state/ and retrieval/.
func validateBundlePath(candidate string) error {
	if candidate == "" || candidate != path.Clean(candidate) || path.IsAbs(candidate) || strings.HasPrefix(candidate, "../") {
		return fmt.Errorf("bundle path %q is not canonical relative", candidate)
	}
	segments := strings.Split(candidate, "/")
	if len(segments) < 2 || len(segments) > 16 {
		return fmt.Errorf("bundle path %q has an unsupported depth", candidate)
	}
	if segments[0] != publishStateDirName && segments[0] != publishRetrievalDirName {
		return fmt.Errorf("bundle path %q is outside the publishable roots", candidate)
	}
	for _, segment := range segments {
		if !publishPathSegmentPattern.MatchString(segment) {
			return fmt.Errorf("bundle path %q holds an unsupported segment %q", candidate, segment)
		}
	}
	return nil
}

// materializeTrustRoot copies the operator allowed-signers file out of its
// mount into a plain read-only regular file. A ConfigMap projection is a
// symlink into ..data/, which the broker rejects by design, so the copy is
// what makes signed-store mode reachable in-cluster at all.
func materializeTrustRoot(source, directory string) error {
	if strings.TrimSpace(source) == "" {
		return errors.New("no allowed-signers trust source was configured")
	}
	raw, err := os.ReadFile(source) // #nosec G304 -- path comes from the operator publish configuration or the validated bundle entry and private staging directory.
	if err != nil {
		return err
	}
	if len(raw) == 0 || int64(len(raw)) > maxControlObjectBytes {
		return fmt.Errorf("allowed-signers trust root is empty or exceeds %d bytes", maxControlObjectBytes)
	}
	if _, err := os.Stat(directory); err == nil {
		return errors.New("bundle supplied its own trust directory")
	}
	if err := os.MkdirAll(directory, publishDirMode); err != nil {
		return err
	}
	destination := filepath.Join(directory, publishTrustFileName)
	if err := os.WriteFile(destination, raw, 0o600); err != nil { // #nosec G703 -- destination is the fixed trust-file child of the private extraction directory.
		return err
	}
	return os.Chmod(destination, publishFileMode)
}

func sealDirectoryTree(root string) error {
	return setDirectoryTreeMode(root, publishSealedDirMode)
}

func unsealDirectoryTree(root string) error {
	return setDirectoryTreeMode(root, publishDirMode)
}

// Directory modes are changed through open descriptors: Root.Chmod on Unix
// can race with a symlink replacement, while File.Chmod keeps the opened inode.
func setDirectoryTreeMode(path string, mode os.FileMode) (err error) {
	root, err := openBoundDirectoryRoot(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open directory tree: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	directories := make([]string, 0, 8)
	err = fs.WalkDir(root.FS(), ".", func(name string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() {
			directories = append(directories, name)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := chmodRootedDirectory(root, directories[index], mode); err != nil {
			return err
		}
	}
	return nil
}

func chmodRootedDirectory(root *os.Root, name string, mode os.FileMode) error {
	file, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("open rooted directory: %w", err)
	}
	info, err := file.Stat()
	if err == nil && !info.IsDir() {
		err = errors.New("rooted mode target is not a directory")
	}
	if err == nil {
		err = file.Chmod(mode)
	}
	return joinCloseError(err, file)
}

func writePublishStatus(target string, status *publishStatus, failure error) error {
	record := status
	if failure != nil || record == nil {
		record = &publishStatus{
			SchemaVersion:    publishBundleSchemaVersion,
			RecordKind:       "knowledge_store_publication_status",
			State:            "degraded",
			PublisherVersion: serverVersion,
		}
		if failure != nil {
			record.Reason = failure.Error()
		}
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(target, publishStatusFileName), append(raw, '\n'), 0o600) // #nosec G304 -- fixed status-file child of the operator-configured publication target.
}
