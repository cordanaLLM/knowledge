package main

import (
	"errors"
	"io"
)

func closeWithError(primary error, closer io.Closer) error {
	return errors.Join(primary, closer.Close())
}
