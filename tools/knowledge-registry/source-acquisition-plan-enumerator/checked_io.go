package main

import (
	"errors"
	"fmt"
	"io"
)

func closeWithError(primary error, closer io.Closer) error {
	if err := closer.Close(); err != nil {
		return errors.Join(primary, fmt.Errorf("close resource: %w", err))
	}
	return primary
}
