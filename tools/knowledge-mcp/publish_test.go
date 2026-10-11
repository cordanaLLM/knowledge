package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// signedFixtureStore is a fully signed, promotable generation store laid out
// exactly as tools/knowledge-mcp/README.md "generation store reader expects".
type signedFixtureStore struct {
	stateDir   string
	trustPath  string
	policyPath string
	policy     []byte
	pointerID  string
	manifestID string
	receiptID  string
}

func buildSignedFixtureStore(t *testing.T) signedFixtureStore {
	t.Helper()
	if _, err := os.Stat(sshKeygenPath); err != nil {
		t.Skip("ssh-keygen is required for signed generation verification")
	}
	stateDir := t.TempDir()
	for _, child := range publishStoreSubdirectories {
		if err := os.Mkdir(filepath.Join(stateDir, child), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := fixtureManifest(t, true)
	writeManifest(t, filepath.Join(stateDir, "manifests", manifest.ManifestID+".json"), manifest)

	keyPath := filepath.Join(t.TempDir(), "signing-key")
	if output, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("generate signing key: %v: %s", err, output)
	}
	public, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := exec.Command("ssh-keygen", "-lf", keyPath+".pub", "-E", "sha256").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	keyID := regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`).FindString(string(fingerprint))
	if keyID == "" {
		t.Fatalf("fingerprint missing from %s", fingerprint)
	}
	actor := "publisher-test"
	policy := []byte(actor + " " + strings.TrimSpace(string(public)) + "\n")
	policyHash := hashBytes(policy)
	trustPath := filepath.Join(t.TempDir(), "operator.allowed_signers")
	if err := os.WriteFile(trustPath, policy, 0o400); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(stateDir, "policies", strings.TrimPrefix(policyHash, "sha256:")+".allowed_signers")
	if err := os.WriteFile(policyPath, policy, 0o400); err != nil {
		t.Fatal(err)
	}

	transitionedAt := "2026-07-20T12:00:00Z"
	intent := map[string]any{
		"schema_version": "2.0.0", "record_kind": "generation_transition_receipt",
		"decision": "promoted", "rollback_of_receipt_id": nil,
		"target_manifest_id": manifest.ManifestID, "target_manifest_hash": manifestHash(manifest),
		"prior_pointer_id": nil, "prior_pointer_hash": nil,
		"transition_assertions": map[string]any{
			"assertion_kind": "promotion", "target_manifest_hash_verified": true,
			"target_schema_validated": true, "target_semantic_validated": true,
			"target_generation_state": "candidate", "input": "complete",
			"enumeration": "complete", "closure": "complete", "identity": "complete",
			"channel_review": "complete", "snapshots": "complete", "promotable": true,
			"reconciliation_complete_mark": true, "candidate_removal_allowed": false,
			"base_binding": "bootstrap", "recomputed_diff_verified": true,
		},
		"removal_allowed": false, "removed": []any{},
		"authorization": map[string]any{
			"actor": actor, "method": generationSignatureMethod, "key_id": keyID,
			"namespace": generationSignatureNamespace, "authorization_policy_hash": policyHash,
		},
		"transitioned_at": transitionedAt,
	}
	payload, err := canonicalJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	sign := exec.Command("ssh-keygen", "-Y", "sign", "-f", keyPath, "-n", generationSignatureNamespace)
	sign.Stdin = bytes.NewReader(payload)
	signature, err := sign.Output()
	if err != nil {
		t.Fatal(err)
	}
	receipt := cloneJSONMap(intent)
	authorization := receipt["authorization"].(map[string]any)
	authorization["signed_payload_hash"] = hashBytes(payload)
	authorization["signature"] = normalizeSignature(string(signature))
	receiptHash, err := canonicalHash(cloneJSONMap(receipt))
	if err != nil {
		t.Fatal(err)
	}
	receiptID := "prc-" + strings.TrimPrefix(receiptHash, "sha256:")
	receipt["receipt_id"] = receiptID

	pointerMap := map[string]any{
		"schema_version": "2.0.0", "record_kind": "generation_pointer", "revision": 1,
		"current_manifest_id": manifest.ManifestID, "current_manifest_hash": manifestHash(manifest),
		"previous_manifest_id": nil, "previous_manifest_hash": nil,
		"transition_receipt_id": receiptID, "updated_at": transitionedAt,
	}
	pointerHash, err := canonicalHash(pointerMap)
	if err != nil {
		t.Fatal(err)
	}
	pointerID := "ptr-" + strings.TrimPrefix(pointerHash, "sha256:")
	pointerMap["pointer_id"] = pointerID
	receipt["resulting_pointer_id"] = pointerID
	receipt["resulting_pointer_hash"] = pointerHash

	writeCanonical(t, filepath.Join(stateDir, "receipts", receiptID+".json"), receipt)
	writeCanonical(t, filepath.Join(stateDir, "pointers", pointerID+".json"), pointerMap)
	writeCanonical(t, filepath.Join(stateDir, publishPointerFileName), pointerMap)

	return signedFixtureStore{
		stateDir: stateDir, trustPath: trustPath, policyPath: policyPath, policy: policy,
		pointerID: pointerID, manifestID: manifest.ManifestID, receiptID: receiptID,
	}
}

func writeCanonical(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// publishTarget returns a scratch target directory and undoes the publisher's
// read-only directory sealing at cleanup so t.TempDir can remove it.
func publishTarget(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	t.Cleanup(func() { unsealDirectoryTree(target) })
	return target
}

func packFixture(t *testing.T, store signedFixtureStore) (string, string) {
	t.Helper()
	output := filepath.Join(t.TempDir(), "bundle.tar")
	receipt, err := packPublishBundle(config{
		publishPack:     store.stateDir,
		publishOutput:   output,
		allowedSigners:  store.trustPath,
		maxRegistrySize: defaultMaxRegistryBytes,
	})
	if err != nil {
		t.Fatalf("pack signed store: %v", err)
	}
	if receipt.PointerID != store.pointerID || receipt.CurrentManifestID != store.manifestID {
		t.Fatalf("receipt does not bind the fixture generation: %#v", receipt)
	}
	return output, receipt.BundleSHA256
}

// repackWithoutVerification models a hostile publisher: it builds a
// well-formed, correctly pinned bundle out of whatever bytes are on disk,
// skipping the pack-time signature gate. The materialize path must still
// reject it.
func repackWithoutVerification(t *testing.T, storeDir string) (string, string) {
	t.Helper()
	entries, sources, err := collectStorePayload(storeDir)
	if err != nil {
		return "", ""
	}
	output := filepath.Join(t.TempDir(), "hostile.tar")
	manifest := publishBundleManifest{
		SchemaVersion:     publishBundleSchemaVersion,
		RecordKind:        publishBundleRecordKind,
		PointerID:         readPointerField(t, storeDir, "pointer_id"),
		CurrentManifestID: readPointerField(t, storeDir, "current_manifest_id"),
		Entries:           entries,
	}
	digest, err := writePublishBundle(output, manifest, sources)
	if err != nil {
		return "", ""
	}
	return output, digest
}

func readPointerField(t *testing.T, storeDir, field string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(storeDir, publishPointerFileName))
	if err != nil {
		return ""
	}
	var pointer map[string]any
	if err := json.Unmarshal(raw, &pointer); err != nil {
		return ""
	}
	value, _ := pointer[field].(string)
	return value
}

func copyStore(t *testing.T, source string) string {
	t.Helper()
	destination := t.TempDir()
	err := filepath.WalkDir(source, func(current string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		if item.IsDir() {
			if relative == "." {
				return nil
			}
			return os.Mkdir(filepath.Join(destination, relative), 0o700)
		}
		raw, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(destination, relative), raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return destination
}

func materializeFixture(t *testing.T, bundlePath, pin, trustSource, target string) (*publishStatus, error) {
	t.Helper()
	return materializePublishBundle(config{
		publishMaterialize: bundlePath,
		publishSHA256:      pin,
		publishTarget:      target,
		publishTrustSource: trustSource,
		maxRegistrySize:    defaultMaxRegistryBytes,
	})
}

func TestPublishRoundTripProducesTheReaderLayoutAndTheBrokerReadsIt(t *testing.T) {
	store := buildSignedFixtureStore(t)
	bundlePath, pin := packFixture(t, store)
	target := publishTarget(t)

	status, err := materializeFixture(t, bundlePath, pin, store.trustPath, target)
	if err != nil {
		t.Fatalf("materialize verified bundle: %v", err)
	}
	if status.State != "published" || status.PointerID != store.pointerID {
		t.Fatalf("unexpected publish status: %#v", status)
	}

	publishedStore := filepath.Join(target, publishStateDirName)
	for _, relative := range []string{
		publishPointerFileName,
		filepath.Join("manifests", store.manifestID+".json"),
		filepath.Join("pointers", store.pointerID+".json"),
		filepath.Join("receipts", store.receiptID+".json"),
		filepath.Join("policies", strings.TrimPrefix(hashBytes(store.policy), "sha256:")+".allowed_signers"),
	} {
		info, statErr := os.Lstat(filepath.Join(publishedStore, relative))
		if statErr != nil {
			t.Fatalf("published layout is missing %s: %v", relative, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			t.Fatalf("published object %s is not a non-symlink regular file", relative)
		}
		if info.Mode().Perm()&0o222 != 0 {
			t.Fatalf("published object %s is writable (%04o)", relative, info.Mode().Perm())
		}
	}

	// The trust root must land outside the store as a plain read-only regular
	// file: a ConfigMap projection is a symlink and the broker rejects those.
	trustPath := filepath.Join(target, publishTrustDirName, publishTrustFileName)
	trustInfo, err := os.Lstat(trustPath)
	if err != nil || trustInfo.Mode()&os.ModeSymlink != 0 || trustInfo.Mode().Perm()&0o222 != 0 {
		t.Fatalf("published trust root is not an immutable regular file: %v %v", trustInfo, err)
	}
	if inside, _ := pathWithin(publishedStore, trustPath); inside {
		t.Fatal("published trust root is inside the generation store")
	}

	snapshot := newRegistryProvider(config{
		stateDirectory:  publishedStore,
		allowedSigners:  trustPath,
		maxRegistrySize: defaultMaxRegistryBytes,
	}).snapshot()
	if snapshot.state != stateOK || snapshot.pointer == nil || snapshot.pointer.PointerID != store.pointerID {
		t.Fatalf("broker rejected the published store: state=%v message=%q", snapshot.state, snapshot.message)
	}
}

func TestPublishBundleIsDeterministic(t *testing.T) {
	store := buildSignedFixtureStore(t)
	_, first := packFixture(t, store)
	_, second := packFixture(t, store)
	if first != second || !validSHA256Hex(first) {
		t.Fatalf("bundle digest is not reproducible: %q vs %q", first, second)
	}
}

func TestPackRefusesAnUnverifiedStore(t *testing.T) {
	for name, damage := range map[string]func(*testing.T, signedFixtureStore) signedFixtureStore{
		"missing receipt": func(t *testing.T, store signedFixtureStore) signedFixtureStore {
			copied := copyStore(t, store.stateDir)
			if err := os.Remove(filepath.Join(copied, "receipts", store.receiptID+".json")); err != nil {
				t.Fatal(err)
			}
			store.stateDir = copied
			return store
		},
		"trust root inside the store": func(t *testing.T, store signedFixtureStore) signedFixtureStore {
			store.trustPath = store.policyPath
			return store
		},
		"unrelated trust root": func(t *testing.T, store signedFixtureStore) signedFixtureStore {
			other := filepath.Join(t.TempDir(), "other.allowed_signers")
			if err := os.WriteFile(other, []byte("attacker ssh-ed25519 AAAA\n"), 0o400); err != nil {
				t.Fatal(err)
			}
			store.trustPath = other
			return store
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := damage(t, buildSignedFixtureStore(t))
			if _, err := packPublishBundle(config{
				publishPack:     store.stateDir,
				publishOutput:   filepath.Join(t.TempDir(), "bundle.tar"),
				allowedSigners:  store.trustPath,
				maxRegistrySize: defaultMaxRegistryBytes,
			}); err == nil {
				t.Fatal("packer published a store the broker would refuse")
			}
		})
	}
}

// TestMaterializeRejectsMutatedStores is the mutation test for the rejection
// path. Each case mutates the signed store, repacks it honestly (correct
// per-entry digests, correct whole-bundle pin) and materializes it. Verification
// must fail, no store may be left behind, and the recorded status must be the
// typed degraded state — never a served, unverified generation.
func TestMaterializeRejectsMutatedStores(t *testing.T) {
	mutations := map[string]func(*testing.T, signedFixtureStore, string){
		"manifest bytes flipped": func(t *testing.T, store signedFixtureStore, dir string) {
			mutateJSONField(t, filepath.Join(dir, "manifests", store.manifestID+".json"), func(document map[string]any) {
				document["generation_state"] = "promoted"
			})
		},
		"receipt signature armor flipped": func(t *testing.T, store signedFixtureStore, dir string) {
			mutateJSONField(t, filepath.Join(dir, "receipts", store.receiptID+".json"), func(document map[string]any) {
				authorization := document["authorization"].(map[string]any)
				armor := authorization["signature"].(string)
				authorization["signature"] = strings.Replace(armor, "A", "B", 1)
			})
		},
		"receipt actor swapped": func(t *testing.T, store signedFixtureStore, dir string) {
			mutateJSONField(t, filepath.Join(dir, "receipts", store.receiptID+".json"), func(document map[string]any) {
				document["authorization"].(map[string]any)["actor"] = "someone-else"
			})
		},
		"pointer revision bumped": func(t *testing.T, store signedFixtureStore, dir string) {
			mutateJSONField(t, filepath.Join(dir, publishPointerFileName), func(document map[string]any) {
				document["revision"] = json.Number("2")
			})
		},
		"pointer alias diverges from its immutable object": func(t *testing.T, store signedFixtureStore, dir string) {
			mutateJSONField(t, filepath.Join(dir, publishPointerFileName), func(document map[string]any) {
				document["updated_at"] = "2026-07-20T13:00:00Z"
			})
		},
		"immutable pointer object removed": func(t *testing.T, store signedFixtureStore, dir string) {
			if err := os.Remove(filepath.Join(dir, "pointers", store.pointerID+".json")); err != nil {
				t.Fatal(err)
			}
		},
		"transition receipt removed": func(t *testing.T, store signedFixtureStore, dir string) {
			if err := os.Remove(filepath.Join(dir, "receipts", store.receiptID+".json")); err != nil {
				t.Fatal(err)
			}
		},
		"persisted policy replaced with an attacker key": func(t *testing.T, store signedFixtureStore, dir string) {
			forged := []byte("publisher-test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
			name := strings.TrimPrefix(hashBytes(forged), "sha256:") + ".allowed_signers"
			if err := os.Remove(filepath.Join(dir, "policies", strings.TrimPrefix(hashBytes(store.policy), "sha256:")+".allowed_signers")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "policies", name), forged, 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"manifest removed entirely": func(t *testing.T, store signedFixtureStore, dir string) {
			if err := os.Remove(filepath.Join(dir, "manifests", store.manifestID+".json")); err != nil {
				t.Fatal(err)
			}
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			store := buildSignedFixtureStore(t)
			mutated := copyStore(t, store.stateDir)

			// Positive control: the unmutated copy travels the same hostile
			// repack path and is accepted, so a blanket rejection cannot make
			// this test pass.
			controlBundle, controlPin := repackWithoutVerification(t, mutated)
			controlTarget := publishTarget(t)
			if controlBundle == "" {
				t.Fatal("control repack failed before mutation")
			}
			if _, err := materializeFixture(t, controlBundle, controlPin, store.trustPath, controlTarget); err != nil {
				t.Fatalf("control materialization of an untouched store failed: %v", err)
			}

			mutate(t, store, mutated)
			bundlePath, pin := repackWithoutVerification(t, mutated)
			target := publishTarget(t)
			if bundlePath == "" {
				// The mutation was already refused at enumeration time (an
				// object whose name no longer matches its bytes). That is the
				// rejection path too, and nothing was published.
				assertNothingPublished(t, target)
				return
			}
			if _, err := materializeFixture(t, bundlePath, pin, store.trustPath, target); err == nil {
				t.Fatal("materializer published a mutated generation store")
			}
			assertNothingPublished(t, target)
		})
	}
}

// TestMaterializeRejectsTamperedBundleEntries covers the transport layer: the
// tar payload is rewritten while the whole-bundle pin is recomputed, so only
// the per-entry digests in bundle.json can catch it.
func TestMaterializeRejectsTamperedBundleEntries(t *testing.T) {
	store := buildSignedFixtureStore(t)
	bundlePath, _ := packFixture(t, store)

	tampered, pin := rewriteBundleEntry(t, bundlePath, "state/"+publishPointerFileName, func(payload []byte) []byte {
		flipped := append([]byte(nil), payload...)
		for index := range flipped {
			if flipped[index] == '1' {
				flipped[index] = '2'
				break
			}
		}
		return flipped
	})
	target := publishTarget(t)
	if _, err := materializeFixture(t, tampered, pin, store.trustPath, target); err == nil {
		t.Fatal("materializer accepted a bundle entry that does not match its manifest digest")
	}
	assertNothingPublished(t, target)
}

func TestMaterializeRejectsAWrongPin(t *testing.T) {
	store := buildSignedFixtureStore(t)
	bundlePath, pin := packFixture(t, store)
	wrong := strings.Repeat("0", 64)
	if pin == wrong {
		t.Fatal("fixture pin collided with the deliberately wrong pin")
	}
	target := publishTarget(t)
	if _, err := materializeFixture(t, bundlePath, wrong, store.trustPath, target); err == nil {
		t.Fatal("materializer accepted a bundle that misses the operator pin")
	}
	assertNothingPublished(t, target)
}

func TestMaterializeRejectsAForeignTrustRoot(t *testing.T) {
	store := buildSignedFixtureStore(t)
	bundlePath, pin := packFixture(t, store)
	foreign := filepath.Join(t.TempDir(), "foreign.allowed_signers")
	if err := os.WriteFile(foreign, []byte("attacker ssh-ed25519 AAAA\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	target := publishTarget(t)
	if _, err := materializeFixture(t, bundlePath, pin, foreign, target); err == nil {
		t.Fatal("materializer accepted a store whose persisted policy is not the operator trust root")
	}
	assertNothingPublished(t, target)
}

func TestBundlePathsRefuseTraversalAndTheTrustRoot(t *testing.T) {
	for _, candidate := range []string{
		"../escape", "/absolute/path", "state/../../escape", "trust/knowledge-registry.allowed_signers",
		"bundle.json", "state", "state//double", "state/.hidden",
	} {
		if err := validateBundlePath(candidate); err == nil {
			t.Fatalf("bundle path %q was accepted", candidate)
		}
	}
	for _, candidate := range []string{"state/generation-pointer.json", "state/manifests/mft-x.json", "retrieval/argocd/store/a.json"} {
		if err := validateBundlePath(candidate); err != nil {
			t.Fatalf("bundle path %q was rejected: %v", candidate, err)
		}
	}
}

func TestPublishConfigRejectsMixedModes(t *testing.T) {
	for name, arguments := range map[string][]string{
		"pack with serving input":  {"--publish-pack", "/tmp/store", "--publish-output", "/tmp/b.tar", "--allowed-signers", "/tmp/t", "--projection", "/tmp/p.sqlite"},
		"pack without output":      {"--publish-pack", "/tmp/store", "--allowed-signers", "/tmp/t"},
		"pack without trust root":  {"--publish-pack", "/tmp/store", "--publish-output", "/tmp/b.tar"},
		"both publish modes":       {"--publish-pack", "/tmp/store", "--publish-materialize", "/tmp/b.tar"},
		"materialize without pin":  {"--publish-materialize", "/tmp/b.tar", "--publish-target", "/tmp/t", "--publish-trust-source", "/tmp/s"},
		"materialize bad pin":      {"--publish-materialize", "/tmp/b.tar", "--publish-sha256", "NOTHEX", "--publish-target", "/tmp/t", "--publish-trust-source", "/tmp/s"},
		"materialize without root": {"--publish-materialize", "/tmp/b.tar", "--publish-sha256", strings.Repeat("a", 64), "--publish-target", "/tmp/t"},
		"publish with mcp-sdk":     {"--publish-materialize", "/tmp/b.tar", "--publish-sha256", strings.Repeat("a", 64), "--publish-target", "/tmp/t", "--publish-trust-source", "/tmp/s", "--mcp-sdk"},
		"orphan publish flag":      {"--publish-target", "/tmp/t"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfig(arguments, func(string) string { return "" }); err == nil {
				t.Fatal("configuration was accepted")
			}
		})
	}
}

func assertNothingPublished(t *testing.T, target string) {
	t.Helper()
	for _, name := range []string{publishStateDirName, publishTrustDirName, publishRetrievalDirName} {
		if _, err := os.Stat(filepath.Join(target, name)); err == nil {
			t.Fatalf("%s survived a failed publication", name)
		}
	}
	raw, err := os.ReadFile(filepath.Join(target, publishStatusFileName))
	if err != nil {
		t.Fatalf("no publication status was recorded: %v", err)
	}
	var status publishStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "degraded" || status.Reason == "" {
		t.Fatalf("failed publication did not record a typed degraded state: %#v", status)
	}
}

func mutateJSONField(t *testing.T, path string, mutate func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rewriteBundleEntry rebuilds a bundle with one payload replaced, leaving
// bundle.json untouched, and returns the recomputed whole-bundle pin.
func rewriteBundleEntry(t *testing.T, bundlePath, entryPath string, mutate func([]byte) []byte) (string, string) {
	t.Helper()
	source, err := os.Open(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	output := filepath.Join(t.TempDir(), "tampered.tar")
	destination, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	digest := sha256.New()
	writer := tar.NewWriter(io.MultiWriter(destination, digest))
	reader := tar.NewReader(source)
	replaced := false
	for {
		header, readErr := reader.Next()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		payload, readErr := io.ReadAll(reader)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if header.Name == entryPath {
			payload = mutate(payload)
			replaced = true
		}
		header.Size = int64(len(payload))
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if !replaced {
		t.Fatalf("bundle entry %q was not found", entryPath)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output, hex.EncodeToString(digest.Sum(nil))
}
