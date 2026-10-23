package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// outputStore pins every write to one opened directory identity. All names
// passed to root are canonical slash-separated relative paths. This prevents a
// pre-created symlink, or a concurrent replacement of StoreRoot, from routing
// any snapshot output outside the directory that was originally validated.
type outputStore struct {
	path string
	root *os.Root
	info fs.FileInfo
}

func openOutputStore(storeRoot string) (*outputStore, error) {
	abs, err := filepath.Abs(storeRoot)
	if err != nil {
		return nil, err
	}
	if err := ensureOutputDirectoryTree(abs); err != nil {
		return nil, err
	}
	if err := validateOutputPath(abs); err != nil {
		return nil, err
	}
	before, err := os.Lstat(abs)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("output store root is not a directory")
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return nil, closeWithError(errors.New("output store root changed while opening"), root)
	}
	store := &outputStore{path: abs, root: root, info: opened}
	if err := store.verifyBinding(); err != nil {
		return nil, closeWithError(err, root)
	}
	return store, nil
}

func (store *outputStore) Close() error { return store.root.Close() }

func (store *outputStore) verifyBinding() error {
	if err := validateOutputPath(store.path); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(store.path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return errors.New("output store root is no longer a directory")
	}
	opened, err := store.root.Stat(".")
	if err != nil || !os.SameFile(store.info, opened) || !os.SameFile(store.info, pathInfo) {
		return errors.New("output store root identity changed during commit")
	}
	return nil
}

func ensureOutputDirectoryTree(directory string) error {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	current := string(filepath.Separator)
	volume := filepath.VolumeName(abs)
	if volume != "" {
		current = volume + string(filepath.Separator)
	}
	relative := strings.TrimPrefix(abs, current)
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, fs.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("output store path contains a symlink or non-directory component")
		}
	}
	return nil
}

func validateOutputPath(candidate string) error {
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return err
	}
	current := string(filepath.Separator)
	volume := filepath.VolumeName(abs)
	if volume != "" {
		current = volume + string(filepath.Separator)
	}
	relative := strings.TrimPrefix(abs, current)
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("output store path contains a symlink or non-directory component")
		}
	}
	return nil
}

func (store *outputStore) ensureDirectories(directory string, mode fs.FileMode) error {
	if directory == "." {
		return nil
	}
	if err := validateRelativePath(directory); err != nil {
		return errors.New("output directory is not canonical and relative")
	}
	current := ""
	for _, component := range strings.Split(directory, "/") {
		if current == "" {
			current = component
		} else {
			current = path.Join(current, component)
		}
		info, err := store.root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err := store.root.Mkdir(current, mode); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			info, err = store.root.Lstat(current)
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("output parent contains a symlink or non-directory component")
		}
	}
	return nil
}

func (store *outputStore) validateDirectories(directory string) error {
	if directory == "." {
		return nil
	}
	if err := validateRelativePath(directory); err != nil {
		return errors.New("output directory is not canonical and relative")
	}
	current := ""
	for _, component := range strings.Split(directory, "/") {
		if current == "" {
			current = component
		} else {
			current = path.Join(current, component)
		}
		info, err := store.root.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("output parent contains a symlink or non-directory component")
		}
	}
	return nil
}

func (store *outputStore) readStable(relative string, maxBytes int64) ([]byte, error) {
	if err := validateRelativePath(relative); err != nil || maxBytes < 0 {
		return nil, errors.New("unsafe rooted object request")
	}
	if err := store.validateDirectories(path.Dir(relative)); err != nil {
		return nil, err
	}
	before, err := store.root.Lstat(relative)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > maxBytes {
		return nil, errors.New("rooted object is not a bounded regular file")
	}
	handle, err := store.root.Open(relative)
	if err != nil {
		return nil, err
	}
	opened, err := handle.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, closeWithError(errors.New("rooted object changed before read"), handle)
	}
	data, readErr := io.ReadAll(io.LimitReader(handle, maxBytes+1))
	closeErr := handle.Close()
	after, statErr := store.root.Lstat(relative)
	if readErr != nil || closeErr != nil || statErr != nil || int64(len(data)) > maxBytes ||
		!os.SameFile(opened, after) || after.Size() != int64(len(data)) || after.ModTime() != opened.ModTime() {
		return nil, errors.New("rooted object changed or exceeded its bound during read")
	}
	return data, nil
}

func (store *outputStore) writeImmutable(relative string, data []byte, mode fs.FileMode) error {
	if err := validateRelativePath(relative); err != nil {
		return errors.New("immutable object path is not canonical and relative")
	}
	parent := path.Dir(relative)
	if err := store.ensureDirectories(parent, 0o755); err != nil {
		return err
	}
	if err := store.validateDirectories(parent); err != nil {
		return err
	}
	if existing, err := store.readStable(relative, int64(len(data))); err == nil {
		if !bytes.Equal(existing, data) {
			return errors.New("immutable path contains different bytes")
		}
		return store.verifyBinding()
	} else if _, statErr := store.root.Lstat(relative); !errors.Is(statErr, fs.ErrNotExist) {
		return errors.New("immutable path exists with unsafe type, size, or bytes")
	}

	tempRelative, err := store.randomChild(parent, ".atomic-")
	if err != nil {
		return err
	}
	temp, err := store.root.OpenFile(tempRelative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer store.root.Remove(tempRelative)
	if _, err := temp.Write(data); err != nil {
		return closeWithError(err, temp)
	}
	if err := temp.Sync(); err != nil {
		return closeWithError(err, temp)
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if staged, err := store.readStable(tempRelative, int64(len(data))); err != nil || !bytes.Equal(staged, data) {
		return errors.New("immutable staged object failed its byte check")
	}

	// Keep both checks adjacent to the only operation that can publish bytes.
	// Root.Link is directory-fd anchored; the component and identity checks make
	// a concurrent swap fail closed rather than silently changing destinations.
	if err := store.validateDirectories(parent); err != nil {
		return err
	}
	if err := store.verifyBinding(); err != nil {
		return err
	}
	created := false
	if err := store.root.Link(tempRelative, relative); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
	} else {
		created = true
	}
	if err := store.validateDirectories(parent); err != nil {
		if created {
			_ = store.root.Remove(relative)
		}
		return err
	}
	if err := store.verifyBinding(); err != nil {
		if created {
			_ = store.root.Remove(relative)
		}
		return err
	}
	existing, err := store.readStable(relative, int64(len(data)))
	if err != nil || !bytes.Equal(existing, data) {
		if created {
			_ = store.root.Remove(relative)
		}
		return errors.New("immutable path collision")
	}
	return store.syncDirectory(parent)
}

func writeImmutableObject(storeRoot, relative string, data []byte, mode fs.FileMode) error {
	store, err := openOutputStore(storeRoot)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.writeImmutable(relative, data, mode)
}

func (store *outputStore) randomChild(parent, prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return path.Join(parent, prefix+hex.EncodeToString(random)), nil
}

func (store *outputStore) createStagingDirectory() (string, error) {
	if err := store.ensureDirectories(".staging", 0o700); err != nil {
		return "", err
	}
	for attempts := 0; attempts < 100; attempts++ {
		relative, err := store.randomChild(".staging", "snapshot-")
		if err != nil {
			return "", err
		}
		if err := store.validateDirectories(".staging"); err != nil {
			return "", err
		}
		if err := store.verifyBinding(); err != nil {
			return "", err
		}
		if err := store.root.Mkdir(relative, 0o700); err == nil {
			return relative, nil
		} else if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("could not allocate unique staging directory")
}

func (store *outputStore) removeAll(relative string) error {
	if err := validateRelativePath(relative); err != nil {
		return errors.New("cleanup path is not canonical and relative")
	}
	return store.root.RemoveAll(relative)
}

func (store *outputStore) syncDirectory(directory string) error {
	if err := store.validateDirectories(directory); err != nil {
		return err
	}
	handle, err := store.root.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func (store *outputStore) verifyDigest(relative, expectedDigest string, expectedSize int64) error {
	if err := validateRelativePath(relative); err != nil {
		return err
	}
	if err := store.validateDirectories(path.Dir(relative)); err != nil {
		return err
	}
	before, err := store.root.Lstat(relative)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.New("rooted object is not a regular file")
	}
	handle, err := store.root.Open(relative)
	if err != nil {
		return err
	}
	opened, err := handle.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return closeWithError(errors.New("rooted object changed before digest read"), handle)
	}
	hash := sha256.New()
	size, readErr := io.Copy(hash, handle)
	closeErr := handle.Close()
	after, statErr := store.root.Lstat(relative)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(opened, after) ||
		after.Size() != size || after.ModTime() != opened.ModTime() {
		return errors.New("rooted object changed during digest read")
	}
	if expectedSize >= 0 && size != expectedSize {
		return errors.New("size mismatch")
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return errors.New("digest mismatch")
	}
	return nil
}

func (store *outputStore) commitStagedObject(stageRelative, targetRelative, digest string) error {
	if err := validateRelativePath(stageRelative); err != nil {
		return err
	}
	if err := validateRelativePath(targetRelative); err != nil {
		return err
	}
	if err := store.verifyDigest(stageRelative, digest, -1); err != nil {
		return err
	}
	targetParent := path.Dir(targetRelative)
	if err := store.ensureDirectories(targetParent, 0o755); err != nil {
		return err
	}
	if err := store.validateDirectories(path.Dir(stageRelative)); err != nil {
		return err
	}
	if err := store.validateDirectories(targetParent); err != nil {
		return err
	}
	// Re-hash immediately before publish so a replaced staging object cannot be
	// admitted under the reviewed digest. The post-link check removes a target
	// created by this operation if the source changes in the final race window.
	if err := store.verifyDigest(stageRelative, digest, -1); err != nil {
		return err
	}
	if err := store.validateDirectories(path.Dir(stageRelative)); err != nil {
		return err
	}
	if err := store.validateDirectories(targetParent); err != nil {
		return err
	}
	if err := store.verifyBinding(); err != nil {
		return err
	}
	created := false
	if err := store.root.Link(stageRelative, targetRelative); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
	} else {
		created = true
	}
	if err := store.validateDirectories(path.Dir(stageRelative)); err != nil {
		if created {
			_ = store.root.Remove(targetRelative)
		}
		return err
	}
	if err := store.validateDirectories(targetParent); err != nil {
		if created {
			_ = store.root.Remove(targetRelative)
		}
		return err
	}
	if err := store.verifyBinding(); err != nil {
		if created {
			_ = store.root.Remove(targetRelative)
		}
		return err
	}
	if err := store.verifyDigest(targetRelative, digest, -1); err != nil {
		if created {
			_ = store.root.Remove(targetRelative)
		}
		return fmt.Errorf("committed object failed identity check: %w", err)
	}
	if err := store.syncDirectory(targetParent); err != nil {
		return err
	}
	return store.root.Remove(stageRelative)
}
