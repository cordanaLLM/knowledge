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
	"slices"
	"sort"
	"strings"
	"syscall"
)

const maxPublishedJSONBytes = int64(16 * 1024 * 1024)

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
	rootFile, err := openCASRoot(absolute)
	if err != nil {
		return nil, err
	}
	info, err := rootFile.Stat()
	if err != nil {
		return nil, closeWithError(fmt.Errorf("inspect output root: %w", err), rootFile)
	}
	if err := validateOwnedDirectory(info, "output root"); err != nil {
		return nil, closeWithError(err, rootFile)
	}
	store := &casStore{root: absolute, rootFile: rootFile, rootInfo: info}
	if err := store.verifyRootPath(); err != nil {
		return nil, closeWithError(err, rootFile)
	}
	if err := store.initializeDirectories(); err != nil {
		return nil, closeWithError(err, rootFile)
	}
	return store, nil
}

func (s *casStore) initializeDirectories() error {
	recoveryState, err := s.hasRecoveryState()
	if err != nil {
		return err
	}
	for _, relative := range []string{"cas", "cas/sha256", "receipts", "inventory-proposals"} {
		if recoveryState {
			directory, _, openErr := s.openStoreDirectory(relative, false)
			if openErr == nil {
				if err := closeWithError(nil, directory); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("recovery state is missing required directory %s: %w", relative, openErr)
		}
		if _, err := s.ensureDirectory(relative); err != nil {
			return err
		}
	}
	return nil
}

func (s *casStore) hasRecoveryState() (bool, error) {
	receipts, _, err := s.listOptionalPublishedDirectory("receipts", 2)
	if err != nil {
		return false, fmt.Errorf("preflight receipts: %w", err)
	}
	proposals, _, err := s.listOptionalPublishedDirectory("inventory-proposals", 2)
	if err != nil {
		return false, fmt.Errorf("preflight inventory proposals: %w", err)
	}
	if len(receipts) == 0 && len(proposals) != 0 {
		return false, errors.New("inventory proposal exists without its predecessor receipt")
	}
	return len(receipts) != 0 || len(proposals) != 0, nil
}

func openCASRoot(absolute string) (file *os.File, err error) {
	parent, err := openDirectoryPathNoFollow(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("output parent: %w", err)
	}
	defer func() {
		err = closeWithError(err, parent)
		if err != nil && file != nil {
			err = closeWithError(err, file)
			file = nil
		}
	}()
	leaf := filepath.Base(absolute)
	file, err = openDirectoryAt(parent, leaf)
	if !errors.Is(err, os.ErrNotExist) {
		return file, err
	}
	if err := syscall.Mkdirat(int(parent.Fd()), leaf, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("create output root: %w", err)
	}
	if err := syncOpenedFile(parent); err != nil {
		return nil, fmt.Errorf("persist output root: %w", err)
	}
	return openDirectoryAt(parent, leaf)
}

func (s *casStore) listOptionalPublishedDirectory(relative string, maximum int) ([]string, bool, error) {
	names, err := s.listPublishedDirectory(relative, maximum)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return names, true, nil
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

func (s *casStore) ensureDirectory(relative string) (result string, err error) {
	directory, _, err := s.openStoreDirectory(relative, true)
	if err != nil {
		return "", err
	}
	defer func() { err = closeWithError(err, directory) }()
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

func (s *casStore) verifyRunSet(receiptPath string, receiptRaw []byte, proposalPath string, proposalRaw []byte) error {
	receipts, err := s.listPublishedDirectory("receipts", 2)
	if err != nil {
		return err
	}
	proposals, err := s.listPublishedDirectory("inventory-proposals", 2)
	if err != nil {
		return err
	}
	if !slices.Equal(receipts, []string{filepath.Base(receiptPath)}) || !slices.Equal(proposals, []string{filepath.Base(proposalPath)}) {
		return errors.New("published receipt/proposal set is incomplete or ambiguous")
	}
	actualReceipt, err := s.readPublished(receiptPath, maxPublishedJSONBytes)
	if err != nil || !bytes.Equal(actualReceipt, receiptRaw) {
		return errors.Join(errors.New("published receipt changed"), err)
	}
	actualProposal, err := s.readPublished(proposalPath, maxPublishedJSONBytes)
	if err != nil || !bytes.Equal(actualProposal, proposalRaw) {
		return errors.Join(errors.New("published proposal changed"), err)
	}
	return nil
}

func (s *casStore) atomicNoReplace(relative string, raw []byte, maximum int64) (err error) {
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
	defer func() { err = closeWithError(err, parent) }()
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
		return closeDescriptorWithError(errors.New("could not own exclusive published object descriptor"), descriptor)
	}
	written, err := writePublishedContents(file, raw)
	if err != nil {
		return closeWithError(err, file)
	}
	return closeWithError(s.commitPublishedContents(parentRelative, parent, parentInfo, leaf, raw, maximum, written), file)
}

func (s *casStore) commitPublishedContents(parentRelative string, parent *os.File, parentInfo os.FileInfo, leaf string, raw []byte, maximum int64, written os.FileInfo) error {
	if err := s.verifyPublishedAtPath(parentRelative, parentInfo, leaf, raw, maximum, written, false, "exclusive published object changed before directory commit"); err != nil {
		return err
	}
	if err := syncOpenedFile(parent); err != nil {
		return err
	}
	if err := s.verifyPublishedAtPath(parentRelative, parentInfo, leaf, raw, maximum, written, false, "exclusive published object changed after directory commit"); err != nil {
		return err
	}
	if err := s.verifyRootPath(); err != nil {
		return err
	}
	return nil
}

func writePublishedContents(file *os.File, raw []byte) (os.FileInfo, error) {
	created, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateOwnedRegular(created, "new published object"); err != nil {
		return nil, err
	}
	if err := writeAll(file, raw); err != nil {
		return nil, err
	}
	if err := syncOpenedFile(file); err != nil {
		return nil, err
	}
	written, err := file.Stat()
	if err != nil || !os.SameFile(created, written) || written.Size() != int64(len(raw)) {
		return nil, errors.Join(errors.New("exclusive published object write is incomplete or unstable"), err)
	}
	return written, nil
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

func verifyPublishedInDirectory(parent *os.File, leaf string, raw []byte, maximum int64, required os.FileInfo, synchronize bool, conflict string) (info os.FileInfo, err error) {
	file, err := openPublishedFile(parent, leaf, synchronize)
	if err != nil {
		return nil, err
	}
	defer func() { err = closeWithError(err, file) }()
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
	existing, after, err := readStablePublished(file, before, maximum)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(existing, raw) {
		return nil, errors.New(conflict)
	}
	if synchronize {
		return synchronizePublished(file, after)
	}
	return after, nil
}

func openPublishedFile(parent *os.File, leaf string, synchronize bool) (*os.File, error) {
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
		return nil, closeDescriptorWithError(errors.New("could not own published object file descriptor"), descriptor)
	}
	return file, nil
}

func readStablePublished(file *os.File, before os.FileInfo, maximum int64) ([]byte, os.FileInfo, error) {
	existing, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(existing)) > maximum {
		return nil, nil, errors.New("published object exceeds its byte bound")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, nil, errors.New("published object changed while it was read")
	}
	return existing, after, nil
}

func synchronizePublished(file *os.File, after os.FileInfo) (os.FileInfo, error) {
	if err := syncOpenedFile(file); err != nil {
		return nil, err
	}
	afterSync, err := file.Stat()
	if err != nil || !os.SameFile(after, afterSync) || after.Size() != afterSync.Size() || after.ModTime() != afterSync.ModTime() {
		return nil, errors.Join(errors.New("published object changed while it was synchronized"), err)
	}
	return afterSync, nil
}

func (s *casStore) verifyPublishedAtPath(parentRelative string, requiredParent os.FileInfo, leaf string, raw []byte, maximum int64, requiredFile os.FileInfo, synchronize bool, conflict string) (err error) {
	parent, parentInfo, err := s.openStoreDirectory(parentRelative, false)
	if err != nil {
		return err
	}
	defer func() { err = closeWithError(err, parent) }()
	if !os.SameFile(requiredParent, parentInfo) {
		return errors.New("published object parent changed during commit")
	}
	_, err = verifyPublishedInDirectory(parent, leaf, raw, maximum, requiredFile, synchronize, conflict)
	return err
}

func (s *casStore) readPublished(relative string, maximum int64) (result []byte, err error) {
	clean := filepath.Clean(relative)
	if clean != relative || filepath.IsAbs(relative) || strings.HasPrefix(clean, "..") {
		return nil, errors.New("published object path is not canonical")
	}
	parentRelative := filepath.Dir(relative)
	parent, parentInfo, err := s.openStoreDirectory(parentRelative, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = closeWithError(err, parent) }()
	leaf := filepath.Base(relative)
	file, err := openPublishedFile(parent, leaf, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = closeWithError(err, file) }()
	before, err := inspectPublished(file, maximum)
	if err != nil {
		return nil, err
	}
	raw, after, err := readStablePublished(file, before, maximum)
	if err != nil {
		return nil, err
	}
	if err := s.verifyPublishedAtPath(parentRelative, parentInfo, leaf, raw, maximum, after, false, "published object changed during path replay"); err != nil {
		return nil, err
	}
	return raw, nil
}

func inspectPublished(file *os.File, maximum int64) (os.FileInfo, error) {
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
	return before, nil
}

func (s *casStore) listPublishedDirectory(relative string, maximum int) (result []string, err error) {
	if maximum < 1 {
		return nil, errors.New("directory entry bound must be positive")
	}
	directory, directoryInfo, err := s.openStoreDirectory(relative, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = closeWithError(err, directory) }()
	entries, err := directory.ReadDir(maximum + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maximum {
		return nil, errors.New("published directory exceeds its entry bound")
	}
	names, err := publishedEntryNames(entries)
	if err != nil {
		return nil, err
	}
	replayed, replayedInfo, err := s.openStoreDirectory(relative, false)
	if err != nil {
		return nil, err
	}
	if err := closeWithError(nil, replayed); err != nil {
		return nil, err
	}
	if !os.SameFile(directoryInfo, replayedInfo) {
		return nil, errors.New("published directory changed while it was listed")
	}
	sort.Strings(names)
	return names, nil
}

func publishedEntryNames(entries []os.DirEntry) ([]string, error) {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return nil, errors.New("published directory contains an unsafe entry name")
		}
		names = append(names, name)
	}
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
	uid, err := checkedUID(os.Geteuid())
	if err != nil {
		return fmt.Errorf("%s ownership: %w", label, err)
	}
	if stat.Uid != uid {
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
		return nil, closeDescriptorWithError(errors.New("could not own filesystem-root descriptor"), descriptor)
	}
	trimmed := strings.TrimPrefix(absolute, string(os.PathSeparator))
	if trimmed == "" {
		return current, nil
	}
	for _, component := range strings.Split(trimmed, string(os.PathSeparator)) {
		if !canonicalDirectoryComponent(component) {
			return nil, closeWithError(errors.New("directory path is not canonical"), current)
		}
		next, err := openDirectoryAt(current, component)
		if closeErr := closeWithError(err, current); closeErr != nil {
			if next != nil {
				closeErr = closeWithError(closeErr, next)
			}
			return nil, closeErr
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
		return nil, closeDescriptorWithError(errors.New("could not own directory descriptor"), descriptor)
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
		return nil, closeDescriptorWithError(errors.New("could not own duplicated directory descriptor"), descriptor)
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
		if !canonicalDirectoryComponent(component) {
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
		next, openErr := openOrCreateDirectoryAt(current, component, create)
		if closeErr := closeWithError(openErr, current); closeErr != nil {
			if next != nil {
				closeErr = closeWithError(closeErr, next)
			}
			return nil, nil, closeErr
		}
		info, statErr := next.Stat()
		if statErr != nil {
			return nil, nil, closeWithError(statErr, next)
		}
		if err := validateOwnedDirectory(info, relative); err != nil {
			return nil, nil, closeWithError(err, next)
		}
		current = next
	}
	info, err := current.Stat()
	if err != nil {
		return nil, nil, closeWithError(err, current)
	}
	return current, info, nil
}

func openOrCreateDirectoryAt(current *os.File, component string, create bool) (*os.File, error) {
	next, openErr := openDirectoryAt(current, component)
	if errors.Is(openErr, os.ErrNotExist) && create {
		if mkdirErr := syscall.Mkdirat(int(current.Fd()), component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
			return nil, mkdirErr
		}
		if syncErr := syncOpenedFile(current); syncErr != nil {
			return nil, syncErr
		}
		next, openErr = openDirectoryAt(current, component)
	}
	return next, openErr
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
		return nil, nil, closeWithError(err, held)
	}
	if err := closeWithError(nil, replayed); err != nil {
		return nil, nil, closeWithError(err, held)
	}
	if !os.SameFile(heldInfo, replayedInfo) {
		return nil, nil, closeWithError(errors.New("store directory changed during path replay"), held)
	}
	if err := s.verifyRootPath(); err != nil {
		return nil, nil, closeWithError(err, held)
	}
	return held, heldInfo, nil
}

func (s *casStore) verifyRootPath() (err error) {
	if s.rootFile == nil {
		return errors.New("store root descriptor is closed")
	}
	current, err := openDirectoryPathNoFollow(s.root)
	if err != nil {
		return fmt.Errorf("reopen output root: %w", err)
	}
	defer func() { err = closeWithError(err, current) }()
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

func canonicalDirectoryComponent(component string) bool {
	return component != "" && component != "." && component != ".."
}
