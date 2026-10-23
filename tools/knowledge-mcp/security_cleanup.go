package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func joinCloseError(cause error, closer io.Closer) error {
	if err := closer.Close(); err != nil {
		return errors.Join(cause, fmt.Errorf("close resource: %w", err))
	}
	return cause
}

func removeFileError(cause error, path string) error {
	if err := os.Remove(path); err != nil {
		return errors.Join(cause, fmt.Errorf("remove temporary file: %w", err))
	}
	return cause
}

func openBoundDirectoryRoot(path string) (*os.Root, error) {
	before, err := os.Lstat(path) // #nosec G703 -- caller-selected directory is bound to the opened root inode below.
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("directory root is not a non-symlink directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil {
		return nil, joinCloseError(err, root)
	}
	if !os.SameFile(before, opened) {
		return nil, joinCloseError(fmt.Errorf("directory root changed while opening"), root)
	}
	return root, nil
}
