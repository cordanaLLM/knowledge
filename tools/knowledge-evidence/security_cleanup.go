package main

import (
	"errors"
	"io"
)

func closeWithError(primary error, closer io.Closer) error {
	return errors.Join(primary, closer.Close())
}

func closeWithIssue(closer io.Closer, code, path, message string) QuarantineIssue {
	return issue(code, path, closeWithError(errors.New(message), closer).Error())
}
