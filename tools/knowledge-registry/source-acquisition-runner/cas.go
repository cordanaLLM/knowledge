package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const maxPublishedJSONBytes = 64 * 1024 * 1024

type casStore struct {
	root     string
	rootFile *os.File
	rootInfo os.FileInfo
}

var syncOpenedFile = func(file *os.File) error { return file.Sync() }

func newCASStore(root string) (*casStore, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if absolute == string(os.PathSeparator) {
		return nil, errors.New("output root must not be the filesystem root")
	}
	parent, err := openDirectoryPathNoFollow(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("output parent: %w", err)
	}
	defer parent.Close()
	leaf := filepath.Base(absolute)
	rootFile, err := openDirectoryAt(parent, leaf)
	if errors.Is(err, os.ErrNotExist) {
		if err := syscall.Mkdirat(int(parent.Fd()), leaf, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
			return nil, fmt.Errorf("create output root: %w", err)
		}
		if err := syncOpenedFile(parent); err != nil {
			return nil, fmt.Errorf("persist output root: %w", err)
		}
		rootFile, err = openDirectoryAt(parent, leaf)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect output root: %w", err)
	}
	info, err := rootFile.Stat()
	if err != nil {
		rootFile.Close()
		return nil, fmt.Errorf("inspect output root: %w", err)
	}
	if err := validateOwnedDirectory(info, "output root"); err != nil {
		rootFile.Close()
		return nil, err
	}
	store := &casStore{root: absolute, rootFile: rootFile, rootInfo: info}
	if err := store.verifyRootPath(); err != nil {
		rootFile.Close()
		return nil, err
	}
	for _, relative := range []string{"cas", "cas/sha256", "receipts", "inventory-proposals"} {
		if _, err := store.ensureDirectory(relative); err != nil {
			rootFile.Close()
			return nil, err
		}
	}
	return store, nil
}

func (s *casStore) close() error {
	if s.rootFile == nil {
		return nil
	}
	err := s.rootFile.Close()
	s.rootFile = nil
	return err
}

func (s *casStore) putBlob(rawSHA256 string, raw []byte) (string, error) {
	hexDigest, err := stripSHA256(rawSHA256)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != hexDigest {
		return "", errors.New("CAS blob bytes do not match requested raw SHA-256")
	}
	directory := filepath.Join("cas", "sha256", hexDigest[:2])
	if _, err := s.ensureDirectory(directory); err != nil {
		return "", err
	}
	relative := filepath.ToSlash(filepath.Join(directory, hexDigest))
	if err := s.atomicNoReplace(relative, raw, int64(len(raw))); err != nil {
		return "", err
	}
	return relative, nil
}

func (s *casStore) putReceipt(receiptID string, raw []byte) (string, error) {
	hexDigest, err := stripPrefixedID(receiptID, "source-acquisition-receipt:sha256:")
	if err != nil {
		return "", err
	}
	relative := filepath.ToSlash(filepath.Join("receipts", hexDigest+".json"))
	if err := s.atomicNoReplace(relative, raw, maxPublishedJSONBytes); err != nil {
		return "", err
	}
	return relative, nil
}

func (s *casStore) putProposal(proposalID string, raw []byte) (string, error) {
	hexDigest, err := stripPrefixedID(proposalID, "source-inventory-proposal:sha256:")
	if err != nil {
		return "", err
	}
	relative := filepath.ToSlash(filepath.Join("inventory-proposals", hexDigest+".json"))
	if err := s.atomicNoReplace(relative, raw, maxPublishedJSONBytes); err != nil {
		return "", err
	}
	return relative, nil
}

func (s *casStore) ensureDirectory(relative string) (string, error) {
	directory, _, err := s.openStoreDirectory(relative, true)
	if err != nil {
		return "", err
	}
	defer directory.Close()
	return filepath.Join(s.root, filepath.FromSlash(relative)), nil
}

func (s *casStore) verifyTargets(targets []targetInventory) error {
	seen := make(map[string]struct{})
	for _, target := range targets {
		for _, file := range target.Files {
			if _, ok := seen[file.RawSHA256]; ok {
				continue
			}
			seen[file.RawSHA256] = struct{}{}
			expectedHex, err := stripSHA256(file.RawSHA256)
			if err != nil {
				return err
			}
			expectedPath := filepath.ToSlash(filepath.Join("cas", "sha256", expectedHex[:2], expectedHex))
			if file.CASPath != expectedPath {
				return errors.New("inventory CAS path is not derived from raw SHA-256")
			}
			raw, err := s.readPublished(file.CASPath, maxBlobBytes)
			if err != nil {
				return fmt.Errorf("inventory CAS object is absent, unsafe, or unstable: %w", err)
			}
			digest := sha256.Sum256(raw)
			if hex.EncodeToString(digest[:]) != expectedHex || int64(len(raw)) != file.Bytes {
				return errors.New("inventory CAS object changed before receipt publication")
			}
		}
	}
	return nil
}

func (s *casStore) atomicNoReplace(relative string, raw []byte, maximum int64) error {
	if int64(len(raw)) > maximum {
		return errors.New("published object exceeds its byte bound")
	}
	clean := filepath.Clean(relative)
	if clean != relative || filepath.IsAbs(relative) || strings.HasPrefix(clean, "..") {
		return errors.New("published object path is not canonical")
	}
	parentRelative := filepath.Dir(relative)
	parent, parentInfo, err := s.openStoreDirectory(parentRelative, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	leaf := filepath.Base(relative)
	descriptor, err := syscall.Openat(int(parent.Fd()), leaf, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return s.rehabilitateExisting(parentRelative, parent, parentInfo, leaf, raw, maximum)
		}
		return err
	}
	file := os.NewFile(uintptr(descriptor), leaf)
	if file == nil {
		syscall.Close(descriptor)
		return errors.New("could not own exclusive published object descriptor")
	}
	created, err := file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	if err := validateOwnedRegular(created, "new published object"); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := writeAll(file, raw); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := syncOpenedFile(file); err != nil {
		return errors.Join(err, file.Close())
	}
	written, err := file.Stat()
	if err != nil || !os.SameFile(created, written) || written.Size() != int64(len(raw)) {
		return errors.Join(errors.New("exclusive published object write is incomplete or unstable"), err, file.Close())
	}
	if err := s.verifyPublishedAtPath(parentRelative, parentInfo, leaf, raw, maximum, written, false, "exclusive published object changed before directory commit"); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := syncOpenedFile(parent); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := s.verifyPublishedAtPath(parentRelative, parentInfo, leaf, raw, maximum, written, false, "exclusive published object changed after directory commit"); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := s.verifyRootPath(); err != nil {
		return errors.Join(err, file.Close())
	}
	return file.Close()
}

func (s *casStore) rehabilitateExisting(parentRelative string, parent *os.File, parentInfo os.FileInfo, leaf string, raw []byte, maximum int64) error {
	identity, err := verifyPublishedInDirectory(parent, leaf, raw, maximum, nil, true, "publication race installed different bytes")
	if err != nil {
		return err
	}
	if err := s.verifyPublishedAtPath(parentRelative, parentInfo, leaf, raw, maximum, identity, false, "published object changed before replay directory commit"); err != nil {
		return err
	}
	if err := syncOpenedFile(parent); err != nil {
		return err
	}
	if err := s.verifyPublishedAtPath(parentRelative, parentInfo, leaf, raw, maximum, identity, false, "published object changed after replay directory commit"); err != nil {
		return err
	}
	return s.verifyRootPath()
}

func verifyPublishedInDirectory(parent *os.File, leaf string, raw []byte, maximum int64, required os.FileInfo, synchronize bool, conflict string) (os.FileInfo, error) {
	access := syscall.O_RDONLY
	if synchronize {
		access = syscall.O_RDWR
	}
	descriptor, err := syscall.Openat(int(parent.Fd()), leaf, access|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("published object path exists and is not a regular file")
		}
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), leaf)
	if file == nil {
		syscall.Close(descriptor)
		return nil, errors.New("could not own published object file descriptor")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateOwnedRegular(before, "published object path"); err != nil {
		return nil, err
	}
	if required != nil && !os.SameFile(required, before) {
		return nil, errors.New("published object path no longer names the writer-owned inode")
	}
	if before.Size() > maximum {
		return nil, errors.New("published object exceeds its byte bound")
	}
	existing, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(existing)) > maximum {
		return nil, errors.New("published object exceeds its byte bound")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, errors.New("published object changed while it was read")
	}
	if !bytes.Equal(existing, raw) {
		return nil, errors.New(conflict)
	}
	if synchronize {
		if err := syncOpenedFile(file); err != nil {
			return nil, err
		}
		afterSync, err := file.Stat()
		if err != nil || !os.SameFile(after, afterSync) || after.Size() != afterSync.Size() || after.ModTime() != afterSync.ModTime() {
			return nil, errors.Join(errors.New("published object changed while it was synchronized"), err)
		}
		after = afterSync
	}
	return after, nil
}

func (s *casStore) verifyPublishedAtPath(parentRelative string, requiredParent os.FileInfo, leaf string, raw []byte, maximum int64, requiredFile os.FileInfo, synchronize bool, conflict string) error {
	parent, parentInfo, err := s.openStoreDirectory(parentRelative, false)
	if err != nil {
		return err
	}
	defer parent.Close()
	if !os.SameFile(requiredParent, parentInfo) {
		return errors.New("published object parent changed during commit")
	}
	_, err = verifyPublishedInDirectory(parent, leaf, raw, maximum, requiredFile, synchronize, conflict)
	return err
}

func (s *casStore) readPublished(relative string, maximum int64) ([]byte, error) {
	clean := filepath.Clean(relative)
	if clean != relative || filepath.IsAbs(relative) || strings.HasPrefix(clean, "..") {
		return nil, errors.New("published object path is not canonical")
	}
	parentRelative := filepath.Dir(relative)
	parent, parentInfo, err := s.openStoreDirectory(parentRelative, false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	leaf := filepath.Base(relative)
	descriptor, err := syscall.Openat(int(parent.Fd()), leaf, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), leaf)
	if file == nil {
		syscall.Close(descriptor)
		return nil, errors.New("could not own published object descriptor")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateOwnedRegular(before, "published object"); err != nil {
		return nil, err
	}
	if before.Size() > maximum {
		return nil, errors.New("published object exceeds its byte bound")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.Join(errors.New("published object read exceeds its bound"), err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, errors.Join(errors.New("published object changed while it was read"), err)
	}
	if err := s.verifyPublishedAtPath(parentRelative, parentInfo, leaf, raw, maximum, after, false, "published object changed during path replay"); err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *casStore) listPublishedDirectory(relative string, maximum int) ([]string, error) {
	if maximum < 1 {
		return nil, errors.New("directory entry bound must be positive")
	}
	directory, directoryInfo, err := s.openStoreDirectory(relative, false)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(maximum + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maximum {
		return nil, errors.New("published directory exceeds its entry bound")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return nil, errors.New("published directory contains an unsafe entry name")
		}
		names = append(names, name)
	}
	replayed, replayedInfo, err := s.openStoreDirectory(relative, false)
	if err != nil {
		return nil, err
	}
	replayed.Close()
	if !os.SameFile(directoryInfo, replayedInfo) {
		return nil, errors.New("published directory changed while it was listed")
	}
	sort.Strings(names)
	return names, nil
}

func writeAll(file *os.File, raw []byte) error {
	for len(raw) > 0 {
		written, err := file.Write(raw)
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("published object write made no progress")
		}
		raw = raw[written:]
	}
	return nil
}

func validateOwnedDirectory(info os.FileInfo, label string) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a real directory", label)
	}
	if err := validateEffectiveOwner(info, label); err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible by group or world", label)
	}
	return nil
}

func validateOwnedRegular(info os.FileInfo, label string) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s exists and is not a regular file", label)
	}
	if err := validateEffectiveOwner(info, label); err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible by group or world", label)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("%s does not have exactly one filesystem link", label)
	}
	return nil
}

func validateEffectiveOwner(info os.FileInfo, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s ownership cannot be verified", label)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is not owned by the effective user", label)
	}
	return nil
}

func openDirectoryPathNoFollow(pathname string) (*os.File, error) {
	absolute, err := filepath.Abs(pathname)
	if err != nil {
		return nil, err
	}
	descriptor, err := syscall.Open(string(os.PathSeparator), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(descriptor), string(os.PathSeparator))
	if current == nil {
		syscall.Close(descriptor)
		return nil, errors.New("could not own filesystem-root descriptor")
	}
	trimmed := strings.TrimPrefix(absolute, string(os.PathSeparator))
	if trimmed == "" {
		return current, nil
	}
	for _, component := range strings.Split(trimmed, string(os.PathSeparator)) {
		if component == "" || component == "." || component == ".." {
			current.Close()
			return nil, errors.New("directory path is not canonical")
		}
		next, err := openDirectoryAt(current, component)
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func openDirectoryAt(parent *os.File, name string) (*os.File, error) {
	descriptor, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		syscall.Close(descriptor)
		return nil, errors.New("could not own directory descriptor")
	}
	return file, nil
}

func duplicateFile(file *os.File, name string) (*os.File, error) {
	descriptor, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(descriptor)
	duplicate := os.NewFile(uintptr(descriptor), name)
	if duplicate == nil {
		syscall.Close(descriptor)
		return nil, errors.New("could not own duplicated directory descriptor")
	}
	return duplicate, nil
}

func validateStoreRelativeDirectory(relative string) ([]string, error) {
	if relative == "." || relative == "" {
		return nil, nil
	}
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, "..") {
		return nil, errors.New("noncanonical store directory")
	}
	components := strings.Split(filepath.ToSlash(relative), "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, errors.New("unsafe store directory component")
		}
	}
	return components, nil
}

func (s *casStore) openDirectoryFromRoot(relative string, create bool) (*os.File, os.FileInfo, error) {
	components, err := validateStoreRelativeDirectory(relative)
	if err != nil {
		return nil, nil, err
	}
	current, err := duplicateFile(s.rootFile, s.root)
	if err != nil {
		return nil, nil, err
	}
	for _, component := range components {
		next, openErr := openDirectoryAt(current, component)
		if errors.Is(openErr, os.ErrNotExist) && create {
			if mkdirErr := syscall.Mkdirat(int(current.Fd()), component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				current.Close()
				return nil, nil, mkdirErr
			}
			if syncErr := syncOpenedFile(current); syncErr != nil {
				current.Close()
				return nil, nil, syncErr
			}
			next, openErr = openDirectoryAt(current, component)
		}
		current.Close()
		if openErr != nil {
			return nil, nil, openErr
		}
		info, statErr := next.Stat()
		if statErr != nil {
			next.Close()
			return nil, nil, statErr
		}
		if err := validateOwnedDirectory(info, relative); err != nil {
			next.Close()
			return nil, nil, err
		}
		current = next
	}
	info, err := current.Stat()
	if err != nil {
		current.Close()
		return nil, nil, err
	}
	return current, info, nil
}

func (s *casStore) openStoreDirectory(relative string, create bool) (*os.File, os.FileInfo, error) {
	if err := s.verifyRootPath(); err != nil {
		return nil, nil, err
	}
	held, heldInfo, err := s.openDirectoryFromRoot(relative, create)
	if err != nil {
		return nil, nil, err
	}
	replayed, replayedInfo, err := s.openDirectoryFromRoot(relative, false)
	if err != nil {
		held.Close()
		return nil, nil, err
	}
	replayed.Close()
	if !os.SameFile(heldInfo, replayedInfo) {
		held.Close()
		return nil, nil, errors.New("store directory changed during path replay")
	}
	if err := s.verifyRootPath(); err != nil {
		held.Close()
		return nil, nil, err
	}
	return held, heldInfo, nil
}

func (s *casStore) verifyRootPath() error {
	if s.rootFile == nil {
		return errors.New("store root descriptor is closed")
	}
	current, err := openDirectoryPathNoFollow(s.root)
	if err != nil {
		return fmt.Errorf("reopen output root: %w", err)
	}
	defer current.Close()
	info, err := current.Stat()
	if err != nil {
		return err
	}
	if err := validateOwnedDirectory(info, "output root"); err != nil {
		return err
	}
	if !os.SameFile(s.rootInfo, info) {
		return errors.New("output root changed after it was opened")
	}
	return nil
}

func stripSHA256(value string) (string, error) {
	return stripPrefixedID(value, "sha256:")
}

func stripPrefixedID(value, prefix string) (string, error) {
	digest := strings.TrimPrefix(value, prefix)
	if digest == value || len(digest) != 64 {
		return "", errors.New("content-addressed ID is malformed")
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("content-addressed ID is malformed")
	}
	if digest != strings.ToLower(digest) {
		return "", errors.New("content-addressed ID is not canonical lowercase")
	}
	return digest, nil
}
