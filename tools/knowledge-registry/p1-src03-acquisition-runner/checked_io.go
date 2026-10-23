package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"syscall"
)

func checkedUID(value int) (uint32, error) {
	if value < 0 || uint64(value) > math.MaxUint32 {
		return 0, fmt.Errorf("effective user id %d is outside uint32 range", value)
	}
	return uint32(value), nil
}

func closeWithError(primary error, closer io.Closer) error {
	if err := closer.Close(); err != nil {
		return errors.Join(primary, fmt.Errorf("close resource: %w", err))
	}
	return primary
}

func closeDescriptorWithError(primary error, descriptor int) error {
	if err := syscall.Close(descriptor); err != nil {
		return errors.Join(primary, fmt.Errorf("close descriptor: %w", err))
	}
	return primary
}
